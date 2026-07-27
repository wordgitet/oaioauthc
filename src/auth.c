/*
** Codex-compatible OAuth credential storage and PKCE token operations.
**
** Codex stores ChatGPT OAuth credentials in auth.json.  This module reads
** that file without requiring fields unrelated to the proxy, writes refreshed
** credentials without discarding unknown Codex fields, and derives an account
** id from a JWT claim when the token response does not name one explicitly.
** The account id is routing metadata required by the Codex backend.
**
** auth_session and oauth_request own all of their string members.  Creation
** and load functions transfer those allocations to the caller; the matching
** free function is safe on a zeroed or partially initialized structure.
**
** JWT payload decoding here is intentionally not signature verification.
** Tokens originate from the OAuth exchange or the local credential file; the
** decoded claim is used only to select a ChatGPT account header.  The backend
** remains the authority that validates the bearer token.
*/

#include <sys/stat.h>

#include <errno.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "auth.h"
#include "http.h"
#include "json.h"
#include "util.h"

#define DEFAULT_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define DEFAULT_ISSUER	  "https://auth.openai.com"
#define DEFAULT_TOKEN_URL "https://auth.openai.com/oauth/token"
#define REFRESH_INTERVAL  3300

/* Format an optional caller-owned diagnostic buffer without allocating. */
static void
set_error(char *error, size_t length, const char *format, ...)
{
	va_list ap;

	if (error == NULL || length == 0)
		return;
	va_start(ap, format);
	(void)vsnprintf(error, length, format, ap);
	va_end(ap);
}

/*
** Encode bytes for OAuth PKCE and JWT transport.
**
** The result is standard Base64 with URL-safe substitutions and no trailing
** padding.  The caller owns the result.  Callers pass small bounded lengths.
*/
static char *
base64url(const unsigned char *data, size_t length)
{
	char  *encoded;
	int    encoded_length;
	size_t index;

	encoded_length = 4 * ((int)length + 2) / 3;
	encoded = malloc((size_t)encoded_length + 1);
	if (encoded == NULL)
		return NULL;
	EVP_EncodeBlock((unsigned char *)encoded, data, (int)length);
	for (index = 0; encoded[index] != '\0'; index++) {
		if (encoded[index] == '+')
			encoded[index] = '-';
		else if (encoded[index] == '/')
			encoded[index] = '_';
	}
	encoded[strcspn(encoded, "=")] = '\0';
	return encoded;
}

/* Obtain cryptographically random bytes, then return their Base64url form. */
static char *
random_urlsafe(size_t length)
{
	unsigned char *bytes;
	char	      *encoded;

	bytes = malloc(length);
	if (bytes == NULL)
		return NULL;
	if (RAND_bytes(bytes, (int)length) != 1) {
		free(bytes);
		return NULL;
	}
	encoded = base64url(bytes, length);
	free(bytes);
	return encoded;
}

/* Return the current UTC time in the auth.json RFC 3339 form. */
static char *
current_timestamp(void)
{
	char	   buffer[32];
	struct tm *utc;
	time_t	   now;

	now = time(NULL);
	utc = gmtime(&now);
	if (utc == NULL ||
	    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", utc) == 0)
		return NULL;
	return oaio_strdup(buffer);
}

/*
** Convert a civil Gregorian date to days since the Unix epoch.
**
** This avoids non-standard timegm(3) and makes refresh timestamp validation
** independent of the process timezone.  parse_timestamp validates all fields
** before calling this arithmetic helper.
*/
static long long
days_from_civil(int year, unsigned int month, unsigned int day)
{
	int	     era;
	unsigned int day_of_era;
	unsigned int day_of_year;
	unsigned int year_of_era;

	year -= month <= 2;
	era = (year >= 0 ? year : year - 399) / 400;
	year_of_era = (unsigned int)(year - era * 400);
	day_of_year = (153 * (month + (month > 2 ? -3U : 9U)) + 2) / 5 + day -
	    1;
	day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 +
	    day_of_year;
	return (long long)era * 146097 + day_of_era - 719468;
}

/*
** Parse exactly the UTC timestamp format emitted by current_timestamp.
**
** Leap years and the time_t conversion are checked explicitly.  A value that
** cannot be represented by the host time_t is not silently wrapped.
*/
static int
parse_timestamp(const char *text, time_t *result)
{
	static const unsigned int month_days[] = { 31, 28, 31, 30, 31, 30, 31,
		31, 30, 31, 30, 31 };
	char			  tail;
	long long		  seconds;
	time_t			  value;
	int			  year;
	unsigned int		  day;
	unsigned int		  days;
	unsigned int		  hour;
	unsigned int		  minute;
	unsigned int		  month;
	unsigned int		  second;

	if (text == NULL ||
	    sscanf(text, "%4d-%2u-%2uT%2u:%2u:%2uZ%c", &year, &month, &day,
		&hour, &minute, &second, &tail) != 6)
		return -1;
	if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 60)
		return -1;
	days = month_days[month - 1];
	if (month == 2 &&
	    (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)))
		days++;
	if (day < 1 || day > days)
		return -1;
	seconds = days_from_civil(year, month, day) * 86400 +
	    (long long)hour * 3600 + (long long)minute * 60 + second;
	value = (time_t)seconds;
	if ((long long)value != seconds)
		return -1;
	*result = value;
	return 0;
}

/*
** Extract chatgpt_account_id from an unverified JWT payload.
**
** The returned string is owned by the caller.  Invalid JWT syntax, invalid
** Base64url, missing JSON, or a missing string claim all return NULL.
*/
static char *
jwt_account_id(const char *token)
{
	const char    *first;
	const char    *second;
	char	      *payload;
	unsigned char *decoded;
	int	       decoded_length;
	size_t	       payload_length;
	size_t	       padding;
	json_error_t   json_error;
	json_t	      *claims;
	json_t	      *auth;
	json_t	      *account;
	char	      *result;

	/*
	 * This extracts routing metadata from a token already obtained through
	 * OAuth; it does not authenticate a JWT or make an authorization decision.
	 */
	if (token == NULL)
		return NULL;
	first = strchr(token, '.');
	if (first == NULL || (second = strchr(first + 1, '.')) == NULL)
		return NULL;
	payload_length = (size_t)(second - first - 1);
	padding = (4 - payload_length % 4) % 4;
	payload = malloc(payload_length + padding + 1);
	if (payload == NULL)
		return NULL;
	memcpy(payload, first + 1, payload_length);
	payload[payload_length] = '\0';
	while (padding > 0) {
		payload[payload_length++] = '=';
		padding--;
	}
	payload[payload_length] = '\0';
	for (first = payload; *first != '\0'; first++) {
		if (*first == '-')
			*(char *)first = '+';
		else if (*first == '_')
			*(char *)first = '/';
	}
	decoded = malloc(strlen(payload) + 1);
	if (decoded == NULL) {
		free(payload);
		return NULL;
	}
	decoded_length = EVP_DecodeBlock(decoded, (unsigned char *)payload,
	    (int)strlen(payload));
	if (decoded_length < 0) {
		free(decoded);
		free(payload);
		return NULL;
	}
	decoded[decoded_length] = '\0';
	claims = json_loads((char *)decoded, 0, &json_error);
	free(decoded);
	free(payload);
	if (claims == NULL)
		return NULL;
	auth = json_object_get(claims, "https://api.openai.com/auth");
	account = json_is_object(auth)
	    ? json_object_get(auth, "chatgpt_account_id")
	    : json_object_get(claims, "chatgpt_account_id");
	result = json_is_string(account)
	    ? oaio_strdup(json_string_value(account))
	    : NULL;
	json_decref(claims);
	return result;
}

/*
** Return the cached default Codex credential path.
**
** CODEX_HOME/auth.json takes precedence; otherwise use ~/.codex/auth.json.
** The returned allocation has process lifetime because configuration is read
** repeatedly by forked workers and never needs a mutable global path.
*/
const char *
auth_default_file(void)
{
	static char *path;
	const char  *codex_home;
	char	    *default_home;

	if (path != NULL)
		return path;
	codex_home = getenv("CODEX_HOME");
	if (codex_home != NULL && codex_home[0] != '\0')
		path = oaio_join_path(codex_home, "auth.json");
	else {
		default_home = oaio_join_path(oaio_home_dir(), ".codex");
		path = default_home == NULL
		    ? NULL
		    : oaio_join_path(default_home, "auth.json");
		free(default_home);
	}
	return path;
}

/* Release every credential string and zero the session for safe reuse. */
void
auth_session_free(struct auth_session *session)
{
	free(session->access_token);
	free(session->refresh_token);
	free(session->id_token);
	free(session->account_id);
	free(session->last_refresh);
	memset(session, 0, sizeof(*session));
}

/*
** Load the subset of Codex auth.json needed for authenticated requests.
**
** access_token and account_id must be available on success.  account_id is
** first read from tokens, then derived from id_token or access_token.  All
** resulting strings belong to session.  On failure session is zeroed and the
** optional error buffer describes a usable recovery action.
*/
int
auth_load(const char *path, struct auth_session *session, char *error,
    size_t length)
{
	struct buffer buffer;
	json_t	     *root;
	json_t	     *tokens;
	const char   *value;

	/* A successful call transfers all duplicated fields to session. */
	memset(session, 0, sizeof(*session));
	buffer_init(&buffer);
	if (read_file(path, &buffer) == -1) {
		set_error(error, length, "could not read auth file: %s",
		    strerror(errno));
		return -1;
	}
	root = json_load_string_checked(buffer.data, error, length);
	buffer_free(&buffer);
	if (root == NULL || !json_is_object(root)) {
		json_decref(root);
		set_error(error, length,
		    "auth file must contain a JSON object");
		return -1;
	}
	tokens = json_object_get(root, "tokens");
	value = json_string_value(json_object_get(tokens, "access_token"));
	session->access_token = value == NULL ? NULL : oaio_strdup(value);
	value = json_string_value(json_object_get(tokens, "refresh_token"));
	session->refresh_token = value == NULL ? NULL : oaio_strdup(value);
	value = json_string_value(json_object_get(tokens, "id_token"));
	session->id_token = value == NULL ? NULL : oaio_strdup(value);
	value = json_string_value(json_object_get(tokens, "account_id"));
	session->account_id = value == NULL ? NULL : oaio_strdup(value);
	if (session->account_id == NULL)
		session->account_id = jwt_account_id(session->id_token);
	if (session->account_id == NULL)
		session->account_id = jwt_account_id(session->access_token);
	value = json_string_value(json_object_get(root, "last_refresh"));
	session->last_refresh = value == NULL ? NULL : oaio_strdup(value);
	json_decref(root);
	if (session->access_token == NULL || session->account_id == NULL) {
		auth_session_free(session);
		set_error(error, length,
		    "auth file does not contain ChatGPT OAuth credentials");
		return -1;
	}
	return 0;
}

/*
** Serialize session credentials with caller-selected replacement behavior.
**
** Replacement preserves unrelated fields from an existing Codex auth.json.
** A new-only save starts from an empty object and uses an atomic no-replace
** installation so a concurrently created credential file remains untouched.
*/
static int
auth_save_internal(const char *path, const struct auth_session *session,
    int replace, char *error, size_t length)
{
	struct buffer buffer;
	json_t	     *root;
	json_t	     *tokens;
	char	     *text;
	int	      result;

	/* Preserve unknown Codex fields so this remains a cooperative auth.json. */
	buffer_init(&buffer);
	root = replace && read_file(path, &buffer) == 0
	    ? json_loads(buffer.data, 0, NULL)
	    : NULL;
	buffer_free(&buffer);
	if (!json_is_object(root)) {
		json_decref(root);
		root = json_object();
	}
	tokens = json_object_get(root, "tokens");
	if (!json_is_object(tokens)) {
		tokens = json_object();
		json_object_set_new(root, "tokens", tokens);
	}
	json_object_set_new(root, "auth_mode", json_string("chatgpt"));
	json_object_set_new(tokens, "access_token",
	    json_string(session->access_token));
	if (session->refresh_token != NULL)
		json_object_set_new(tokens, "refresh_token",
		    json_string(session->refresh_token));
	if (session->id_token != NULL)
		json_object_set_new(tokens, "id_token",
		    json_string(session->id_token));
	json_object_set_new(tokens, "account_id",
	    json_string(session->account_id));
	if (session->last_refresh != NULL)
		json_object_set_new(root, "last_refresh",
		    json_string(session->last_refresh));
	text = json_dumps(root, JSON_INDENT(2));
	json_decref(root);
	if (text == NULL) {
		set_error(error, length, "could not serialize auth file");
		return -1;
	}
	result = replace ? write_private_file(path, text)
			 : write_private_file_new(path, text);
	if (result == -1) {
		free(text);
		if (!replace && errno == EEXIST)
			set_error(error, length,
			    "auth file appeared during login; credentials were not replaced");
		else
			set_error(error, length,
			    "could not write auth file: %s", strerror(errno));
		return -1;
	}
	free(text);
	return 0;
}

/*
** Merge session credentials into a Codex-compatible auth.json file.
**
** Readers see old complete credentials or new complete credentials, never a
** partially serialized file.
*/
int
auth_save(const char *path, const struct auth_session *session, char *error,
    size_t length)
{
	return auth_save_internal(path, session, 1, error, length);
}

/* Atomically install a new credential file without replacing another writer. */
int
auth_save_new(const char *path, const struct auth_session *session, char *error,
    size_t length)
{
	return auth_save_internal(path, session, 0, error, length);
}

/*
** Decide whether session should be refreshed before an upstream call.
**
** JWT access tokens refresh five minutes before exp.  Opaque tokens fall back
** to last_refresh and REFRESH_INTERVAL.  Missing or unreadable refresh timing
** is treated as needing refresh: serving with a stale token is not useful.
*/
int
auth_session_needs_refresh(const struct auth_session *session)
{
	const char    *first;
	const char    *second;
	char	      *payload;
	unsigned char *decoded;
	int	       decoded_length;
	size_t	       payload_length;
	size_t	       padding;
	json_t	      *claims;
	json_int_t     expires;
	int	       result;
	time_t	       refreshed;

	/* Prefer JWT expiry, then retain a conservative interval for opaque tokens. */
	if (session->access_token == NULL || session->refresh_token == NULL)
		return session->access_token == NULL;
	first = strchr(session->access_token, '.');
	if (first == NULL || (second = strchr(first + 1, '.')) == NULL)
		goto check_last_refresh;
	payload_length = (size_t)(second - first - 1);
	padding = (4 - payload_length % 4) % 4;
	payload = malloc(payload_length + padding + 1);
	if (payload == NULL)
		goto check_last_refresh;
	memcpy(payload, first + 1, payload_length);
	while (padding > 0) {
		payload[payload_length++] = '=';
		padding--;
	}
	payload[payload_length] = '\0';
	for (first = payload; *first != '\0'; first++) {
		if (*first == '-')
			*(char *)first = '+';
		else if (*first == '_')
			*(char *)first = '/';
	}
	decoded = malloc(payload_length + 1);
	if (decoded == NULL) {
		free(payload);
		goto check_last_refresh;
	}
	decoded_length = EVP_DecodeBlock(decoded, (unsigned char *)payload,
	    (int)payload_length);
	free(payload);
	if (decoded_length < 0) {
		free(decoded);
		goto check_last_refresh;
	}
	decoded[decoded_length] = '\0';
	claims = json_loads((char *)decoded, 0, NULL);
	free(decoded);
	if (!json_is_object(claims)) {
		json_decref(claims);
		goto check_last_refresh;
	}
	expires = json_integer_value(json_object_get(claims, "exp"));
	json_decref(claims);
	result = expires > 0 && expires <= (json_int_t)time(NULL) + 300;
	if (result)
		return 1;

check_last_refresh:
	if (parse_timestamp(session->last_refresh, &refreshed) == 0)
		return refreshed <= time(NULL) - REFRESH_INTERVAL;
	return 1;
}

/*
** Merge a successful OAuth token response into session.
**
** Refresh responses may omit refresh_token, id_token, or account_id.  Existing
** values are retained when safe, and account-id discovery follows the same
** fallback order as auth_load.  session remains caller-owned on all paths.
*/
static int
token_response(const char *text, struct auth_session *session, char *error,
    size_t length)
{
	json_t	   *root;
	const char *value;
	char	   *account;

	root = json_load_string_checked(text, error, length);
	if (root == NULL)
		return -1;
	value = json_string_value(json_object_get(root, "access_token"));
	if (value == NULL) {
		json_decref(root);
		set_error(error, length, "token response has no access_token");
		return -1;
	}
	free(session->access_token);
	session->access_token = oaio_strdup(value);
	value = json_string_value(json_object_get(root, "refresh_token"));
	if (value != NULL) {
		free(session->refresh_token);
		session->refresh_token = oaio_strdup(value);
	}
	value = json_string_value(json_object_get(root, "id_token"));
	if (value != NULL) {
		free(session->id_token);
		session->id_token = oaio_strdup(value);
	}
	value = json_string_value(json_object_get(root, "account_id"));
	account = value == NULL ? jwt_account_id(session->id_token)
				: oaio_strdup(value);
	if (account == NULL)
		account = jwt_account_id(session->access_token);
	if (account == NULL && session->account_id != NULL)
		account = oaio_strdup(session->account_id);
	if (account == NULL) {
		json_decref(root);
		set_error(error, length,
		    "token response has no ChatGPT account id");
		return -1;
	}
	free(session->account_id);
	session->account_id = account;
	free(session->last_refresh);
	session->last_refresh = current_timestamp();
	json_decref(root);
	return session->access_token == NULL || session->last_refresh == NULL
	    ? -1
	    : 0;
}

/*
** Refresh an existing session and persist the replacement credentials.
**
** The in-memory session is updated before auth_save.  A save failure therefore
** returns an error even though the caller holds a usable fresh token: later
** workers would otherwise reload the stale on-disk session.
*/
int
auth_refresh(const char *path, const char *client_id, const char *token_url,
    struct auth_session *session, char *error, size_t length)
{
	struct http_response response;
	json_t		    *body;
	char		    *text;
	int		     result;

	if (session->refresh_token == NULL) {
		set_error(error, length, "auth file has no refresh token");
		return -1;
	}
	body = json_pack("{s:s,s:s,s:s}", "grant_type", "refresh_token",
	    "refresh_token", session->refresh_token, "client_id",
	    client_id == NULL ? DEFAULT_CLIENT_ID : client_id);
	if (body == NULL)
		return -1;
	text = json_dump_compact(body);
	json_decref(body);
	if (text == NULL)
		return -1;
	result =
	    http_post_json(token_url == NULL ? DEFAULT_TOKEN_URL : token_url,
		text, NULL, NULL, NULL, &response, error, length);
	free(text);
	if (result == -1)
		return -1;
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "token refresh failed with HTTP %ld",
		    response.status);
		http_response_free(&response);
		return -1;
	}
	result = token_response(response.body, session, error, length);
	http_response_free(&response);
	if (result == 0)
		result = auth_save(path, session, error, length);
	return result;
}

/*
** Create a complete authorization URL and the PKCE state needed to finish it.
**
** authorization_url, state, and code_verifier are all returned in request and
** are owned by the caller.  Failure leaves request safe for oauth_request_free.
*/
int
oauth_request_create(const char *redirect_uri, const char *client_id,
    struct oauth_request *request, char *error, size_t length)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_length;
	char	     *challenge;
	char	     *escaped_redirect;
	struct buffer url;

	/* state prevents callback substitution; S256 binds the code to this client. */
	memset(request, 0, sizeof(*request));
	request->state = random_urlsafe(24);
	request->code_verifier = random_urlsafe(48);
	if (request->state == NULL || request->code_verifier == NULL ||
	    EVP_Digest(request->code_verifier, strlen(request->code_verifier),
		digest, &digest_length, EVP_sha256(), NULL) != 1) {
		set_error(error, length, "could not create OAuth PKCE request");
		oauth_request_free(request);
		return -1;
	}
	challenge = base64url(digest, digest_length);
	escaped_redirect = http_form_encode(redirect_uri);
	buffer_init(&url);
	if (challenge == NULL || escaped_redirect == NULL ||
	    buffer_append_string(&url,
		DEFAULT_ISSUER
		"/oauth/authorize?response_type=code&client_id=") == -1 ||
	    buffer_append_string(&url,
		client_id == NULL ? DEFAULT_CLIENT_ID : client_id) == -1 ||
	    buffer_append_string(&url, "&redirect_uri=") == -1 ||
	    buffer_append_string(&url, escaped_redirect) == -1 ||
	    buffer_append_string(&url,
		"&scope=openid%20profile%20email%20offline_access&state=") ==
		-1 ||
	    buffer_append_string(&url, request->state) == -1 ||
	    buffer_append_string(&url, "&code_challenge=") == -1 ||
	    buffer_append_string(&url, challenge) == -1 ||
	    buffer_append_string(&url,
		"&code_challenge_method=S256"
		"&id_token_add_organizations=true"
		"&codex_cli_simplified_flow=true") == -1) {
		free(challenge);
		free(escaped_redirect);
		buffer_free(&url);
		oauth_request_free(request);
		return -1;
	}
	free(challenge);
	free(escaped_redirect);
	request->authorization_url = buffer_steal(&url);
	return 0;
}

/* Release a completed or partially built PKCE request. */
void
oauth_request_free(struct oauth_request *request)
{
	free(request->authorization_url);
	free(request->state);
	free(request->code_verifier);
	memset(request, 0, sizeof(*request));
}

/*
** Exchange the validated authorization code for OAuth credentials.
**
** Every form value is encoded independently before assembly.  This function
** only updates session after a 2xx token response passes token_response; it
** deliberately does not save auth.json because the interactive caller chooses
** the destination path after the exchange succeeds.
*/
int
oauth_exchange_code(const char *code, const char *code_verifier,
    const char *redirect_uri, const char *client_id, const char *token_url,
    oauth_cancel_callback cancel, void *cancel_argument,
    struct auth_session *session, char *error, size_t length)
{
	char		    *escaped_code;
	char		    *escaped_verifier;
	char		    *escaped_redirect;
	struct buffer	     body;
	struct http_response response;
	int		     result;

	escaped_code = http_form_encode(code);
	escaped_verifier = http_form_encode(code_verifier);
	escaped_redirect = http_form_encode(redirect_uri);
	if (escaped_code == NULL || escaped_verifier == NULL ||
	    escaped_redirect == NULL) {
		free(escaped_code);
		free(escaped_verifier);
		free(escaped_redirect);
		return -1;
	}
	buffer_init(&body);
	(void)buffer_append_string(&body,
	    "grant_type=authorization_code&code=");
	(void)buffer_append_string(&body, escaped_code);
	(void)buffer_append_string(&body, "&redirect_uri=");
	(void)buffer_append_string(&body, escaped_redirect);
	(void)buffer_append_string(&body, "&client_id=");
	(void)buffer_append_string(&body,
	    client_id == NULL ? DEFAULT_CLIENT_ID : client_id);
	(void)buffer_append_string(&body, "&code_verifier=");
	(void)buffer_append_string(&body, escaped_verifier);
	free(escaped_code);
	free(escaped_verifier);
	free(escaped_redirect);
	result =
	    http_post_form(token_url == NULL ? DEFAULT_TOKEN_URL : token_url,
		body.data, cancel, cancel_argument, &response, error, length);
	buffer_free(&body);
	if (result == -1)
		return -1;
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "token exchange failed with HTTP %ld",
		    response.status);
		http_response_free(&response);
		return -1;
	}
	result = token_response(response.body, session, error, length);
	http_response_free(&response);
	return result;
}
