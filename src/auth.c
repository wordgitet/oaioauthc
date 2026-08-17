/*
** Codex-compatible OAuth credential storage and PKCE token operations.
**
** Codex stores ChatGPT OAuth credentials in auth.json.  This module reads
** that file without requiring fields unrelated to the proxy, writes refreshed
** credentials without discarding unknown Codex fields, and derives an account
** id from a JWT claim when the token response does not name one explicitly.
** The account id is routing metadata required by the Codex backend.
** It also implements the issuer-aware browser PKCE request and the Codex
** headless device-code request, polling, and final token exchange.
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
#include <fcntl.h>
#include <jansson.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "http.h"
#include "json.h"
#include "secret.h"
#include "util.h"

#define DEFAULT_CLIENT_ID    "app_EMoamEEZ73f0CkXaXp7hrann"
#define DEFAULT_ISSUER	     "https://auth.openai.com"
#define DEFAULT_TOKEN_URL    "https://auth.openai.com/oauth/token"
#define ACCOUNT_ID_MAX	     4096
#define DEVICE_AUTH_ID_MAX   4096
#define DEVICE_CODE_MAX	     8192
#define DEVICE_USER_CODE_MAX 64
#define OAUTH_TOKEN_MAX	     (1024 * 1024)
#define REFRESH_INTERVAL     3300

/* Join an issuer root to a protocol path without producing a double slash. */
static char *
issuer_endpoint(const char *issuer, const char *path)
{
	const char *base;
	size_t	    base_length;
	size_t	    path_length;
	char	   *result;

	base = issuer == NULL || issuer[0] == '\0' ? DEFAULT_ISSUER : issuer;
	base_length = strlen(base);
	while (base_length > 0 && base[base_length - 1] == '/')
		base_length--;
	path_length = strlen(path);
	if (base_length > (size_t)-1 - path_length - 1)
		return NULL;
	result = malloc(base_length + path_length + 1);
	if (result == NULL)
		return NULL;
	memcpy(result, base, base_length);
	memcpy(result + base_length, path, path_length + 1);
	return result;
}

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
** Borrow one non-empty JSON string only when every byte is visible to C APIs.
**
** Jansson strings can contain embedded NUL bytes.  Rejecting those values
** prevents validation, logging, or form encoding from seeing a shorter string
** than the JSON parser accepted.  The size cap also bounds later copies.
*/
static int
json_bounded_string(json_t *value, size_t maximum, const char **text)
{
	const char *string;
	size_t	    string_length;

	string = json_string_value(value);
	if (string == NULL)
		return -1;
	string_length = json_string_length(value);
	if (string_length == 0 || string_length > maximum ||
	    strlen(string) != string_length)
		return -1;
	*text = string;
	return 0;
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

/* Verify that a device response did not pair a code with the wrong verifier. */
static int
device_pkce_matches(const char *code_verifier, const char *code_challenge)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_length;
	char	     *computed;
	int	      result;

	if (EVP_Digest(code_verifier, strlen(code_verifier), digest,
		&digest_length, EVP_sha256(), NULL) != 1)
		return -1;
	computed = base64url(digest, digest_length);
	if (computed == NULL)
		return -1;
	result = strcmp(computed, code_challenge) == 0 ? 0 : -1;
	free(computed);
	return result;
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
		secret_clear(bytes, length);
		free(bytes);
		return NULL;
	}
	encoded = base64url(bytes, length);
	secret_clear(bytes, length);
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
		secret_free(payload);
		return NULL;
	}
	decoded_length = EVP_DecodeBlock(decoded, (unsigned char *)payload,
	    (int)strlen(payload));
	if (decoded_length < 0) {
		secret_clear(decoded, strlen(payload) + 1);
		free(decoded);
		secret_free(payload);
		return NULL;
	}
	decoded[decoded_length] = '\0';
	claims = json_loads((char *)decoded, 0, &json_error);
	secret_clear(decoded, strlen(payload) + 1);
	free(decoded);
	secret_free(payload);
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

/* Expose the stable issuer default without duplicating it in the CLI. */
const char *
oauth_default_issuer(void)
{
	return DEFAULT_ISSUER;
}

/* Release every credential string and zero the session for safe reuse. */
void
auth_session_free(struct auth_session *session)
{
	secret_free(session->access_token);
	secret_free(session->refresh_token);
	secret_free(session->id_token);
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
		secret_buffer_free(&buffer);
		set_error(error, length, "could not read auth file: %s",
		    strerror(errno));
		return -1;
	}
	root = json_load_buffer_checked(buffer.data, buffer.len, error, length);
	secret_buffer_free(&buffer);
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
	secret_buffer_free(&buffer);
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
		secret_free(text);
		if (!replace && errno == EEXIST)
			set_error(error, length,
			    "auth file appeared during login; credentials were not replaced");
		else
			set_error(error, length,
			    "could not write auth file: %s", strerror(errno));
		return -1;
	}
	secret_free(text);
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
		secret_free(payload);
		goto check_last_refresh;
	}
	decoded_length = EVP_DecodeBlock(decoded, (unsigned char *)payload,
	    (int)payload_length);
	secret_free(payload);
	if (decoded_length < 0) {
		secret_clear(decoded, payload_length + 1);
		free(decoded);
		goto check_last_refresh;
	}
	decoded[decoded_length] = '\0';
	claims = json_loads((char *)decoded, 0, NULL);
	secret_clear(decoded, payload_length + 1);
	free(decoded);
	if (!json_is_object(claims)) {
		json_decref(claims);
		goto check_last_refresh;
	}
	expires = json_integer_value(json_object_get(claims, "exp"));
	json_decref(claims);
	/*
	** A usable JWT expiry is authoritative.  Falling through to last_refresh
	** would refresh a valid token repeatedly when older auth files omit it.
	*/
	if (expires > 0) {
		result = expires <= (json_int_t)time(NULL) + 300;
		return (result);
	}

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
token_response(const char *text, size_t text_length, int require_complete,
    struct auth_session *session, char *error, size_t length)
{
	json_t	   *root;
	json_t	   *field;
	const char *access_token;
	const char *account_id;
	const char *id_token;
	const char *refresh_token;
	char	   *account;
	char	   *new_access_token;
	char	   *new_id_token;
	char	   *new_last_refresh;
	char	   *new_refresh_token;

	account = NULL;
	new_access_token = NULL;
	new_id_token = NULL;
	new_last_refresh = NULL;
	new_refresh_token = NULL;
	root = json_load_buffer_checked(text, text_length, error, length);
	if (root == NULL)
		return -1;
	field = json_object_get(root, "access_token");
	if (json_bounded_string(field, OAUTH_TOKEN_MAX, &access_token) == -1) {
		set_error(error, length,
		    "token response has no usable access_token");
		goto fail;
	}
	new_access_token = oaio_strdup(access_token);
	field = json_object_get(root, "refresh_token");
	refresh_token = NULL;
	if (field != NULL &&
	    json_bounded_string(field, OAUTH_TOKEN_MAX, &refresh_token) == -1) {
		set_error(error, length,
		    "token response has invalid refresh_token");
		goto fail;
	}
	field = json_object_get(root, "id_token");
	id_token = NULL;
	if (field != NULL &&
	    json_bounded_string(field, OAUTH_TOKEN_MAX, &id_token) == -1) {
		set_error(error, length, "token response has invalid id_token");
		goto fail;
	}
	if (require_complete &&
	    (refresh_token == NULL || refresh_token[0] == '\0' ||
		id_token == NULL || id_token[0] == '\0')) {
		set_error(error, length,
		    "token response is missing initial OAuth credentials");
		goto fail;
	}
	if (refresh_token != NULL)
		new_refresh_token = oaio_strdup(refresh_token);
	if (id_token != NULL)
		new_id_token = oaio_strdup(id_token);
	if (new_access_token == NULL ||
	    (refresh_token != NULL && new_refresh_token == NULL) ||
	    (id_token != NULL && new_id_token == NULL)) {
		set_error(error, length, "could not allocate token response");
		goto fail;
	}
	field = json_object_get(root, "account_id");
	account_id = NULL;
	if (field != NULL &&
	    json_bounded_string(field, ACCOUNT_ID_MAX, &account_id) == -1) {
		set_error(error, length,
		    "token response has invalid account_id");
		goto fail;
	}
	account = account_id == NULL
	    ? jwt_account_id(
		  id_token == NULL ? session->id_token : new_id_token)
	    : oaio_strdup(account_id);
	if (account == NULL)
		account = jwt_account_id(new_access_token);
	if (account == NULL && session->account_id != NULL)
		account = oaio_strdup(session->account_id);
	if (account == NULL) {
		set_error(error, length,
		    "token response has no ChatGPT account id");
		goto fail;
	}
	new_last_refresh = current_timestamp();
	if (new_last_refresh == NULL) {
		set_error(error, length, "could not record token refresh time");
		goto fail;
	}
	secret_free(session->access_token);
	session->access_token = new_access_token;
	new_access_token = NULL;
	if (refresh_token != NULL) {
		secret_free(session->refresh_token);
		session->refresh_token = new_refresh_token;
		new_refresh_token = NULL;
	}
	if (id_token != NULL) {
		secret_free(session->id_token);
		session->id_token = new_id_token;
		new_id_token = NULL;
	}
	free(session->account_id);
	session->account_id = account;
	account = NULL;
	free(session->last_refresh);
	session->last_refresh = new_last_refresh;
	new_last_refresh = NULL;
	json_decref(root);
	return 0;

fail:
	free(account);
	secret_free(new_access_token);
	secret_free(new_id_token);
	free(new_last_refresh);
	secret_free(new_refresh_token);
	json_decref(root);
	return -1;
}

/*
** Refresh the currently locked session and persist replacement credentials.
**
** The in-memory session is updated before auth_save.  A save failure therefore
** returns an error even though the caller holds a usable fresh token: later
** workers would otherwise reload the stale on-disk session.
*/
static int
auth_refresh_locked(const char *path, const char *client_id,
    const char *token_url, struct auth_session *session, char *error,
    size_t length)
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
		text, NULL, NULL, NULL, NULL, NULL, &response, error, length);
	secret_free(text);
	if (result == -1)
		return -1;
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "token refresh failed with HTTP %ld",
		    response.status);
		secret_clear(response.body, response.body_length);
		http_response_free(&response);
		return -1;
	}
	result = token_response(response.body, response.body_length, 0, session,
	    error, length);
	secret_clear(response.body, response.body_length);
	http_response_free(&response);
	if (result == 0)
		result = auth_save(path, session, error, length);
	return result;
}

/*
** Acquire the stable sibling lock used to serialize auth.json refreshes.
**
** auth.json itself is atomically renamed, so locking that inode would not
** coordinate a worker that opens the replacement.  The persistent .lock path
** keeps every process on the same advisory lock across credential replacements.
*/
static int
auth_refresh_lock(const char *path, char *error, size_t length)
{
	struct buffer lock_path;
	struct flock  lock;
	int	      fd;
	int	      saved_errno;

	buffer_init(&lock_path);
	if (buffer_append_string(&lock_path, path) == -1 ||
	    buffer_append_string(&lock_path, ".lock") == -1) {
		buffer_free(&lock_path);
		set_error(error, length,
		    "could not allocate auth refresh lock path");
		return (-1);
	}
	fd = open(lock_path.data, O_CREAT | O_RDWR, 0600);
	if (fd == -1) {
		saved_errno = errno;
		buffer_free(&lock_path);
		errno = saved_errno;
		set_error(error, length, "could not open auth refresh lock: %s",
		    strerror(errno));
		return (-1);
	}
	buffer_free(&lock_path);
	if (fchmod(fd, 0600) == -1) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		set_error(error, length,
		    "could not secure auth refresh lock: %s", strerror(errno));
		return (-1);
	}
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	while (fcntl(fd, F_SETLKW, &lock) == -1) {
		if (errno == EINTR)
			continue;
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		set_error(error, length,
		    "could not acquire auth refresh lock: %s", strerror(errno));
		return (-1);
	}
	return (fd);
}

/*
** Serialize refreshes, then reload auth.json before deciding whether to renew.
**
** A worker may wait while another process rotates and saves the refresh token.
** Reloading under the sibling lock lets the waiter adopt that completed session
** instead of exchanging and later saving credentials derived from stale state.
*/
int
auth_refresh(const char *path, const char *client_id, const char *token_url,
    struct auth_session *session, char *error, size_t length)
{
	struct auth_session current;
	int		    lock_fd;
	int		    result;

	lock_fd = auth_refresh_lock(path, error, length);
	if (lock_fd == -1)
		return (-1);
	result = auth_load(path, &current, error, length);
	if (result == 0) {
		auth_session_free(session);
		*session = current;
		if (auth_session_needs_refresh(session))
			result = auth_refresh_locked(path, client_id, token_url,
			    session, error, length);
	}
	if (close(lock_fd) == -1 && result == 0) {
		set_error(error, length,
		    "could not release auth refresh lock: %s", strerror(errno));
		return -1;
	}
	return (result);
}

/*
** Create a complete authorization URL and the PKCE state needed to finish it.
**
** authorization_url, state, and code_verifier are all returned in request and
** are owned by the caller.  Failure leaves request safe for oauth_request_free.
*/
int
oauth_request_create(const char *issuer, const char *redirect_uri,
    const char *client_id, struct oauth_request *request, char *error,
    size_t length)
{
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  digest_length;
	char	     *challenge;
	char	     *escaped_client;
	char	     *escaped_redirect;
	char	     *authorize_endpoint;
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
	escaped_client = http_form_encode(
	    client_id == NULL ? DEFAULT_CLIENT_ID : client_id);
	escaped_redirect = http_form_encode(redirect_uri);
	authorize_endpoint = issuer_endpoint(issuer, "/oauth/authorize");
	buffer_init(&url);
	if (challenge == NULL || escaped_client == NULL ||
	    escaped_redirect == NULL || authorize_endpoint == NULL ||
	    buffer_append_string(&url, authorize_endpoint) == -1 ||
	    buffer_append_string(&url, "?response_type=code&client_id=") ==
		-1 ||
	    buffer_append_string(&url, escaped_client) == -1 ||
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
		set_error(error, length,
		    "could not build OAuth authorization URL");
		free(challenge);
		free(escaped_client);
		free(escaped_redirect);
		free(authorize_endpoint);
		secret_buffer_free(&url);
		oauth_request_free(request);
		return -1;
	}
	free(challenge);
	free(escaped_client);
	free(escaped_redirect);
	free(authorize_endpoint);
	request->authorization_url = buffer_steal(&url);
	if (request->authorization_url == NULL) {
		set_error(error, length,
		    "could not allocate OAuth authorization URL");
		oauth_request_free(request);
		return -1;
	}
	return 0;
}

/* Release a completed or partially built PKCE request. */
void
oauth_request_free(struct oauth_request *request)
{
	secret_free(request->authorization_url);
	secret_free(request->state);
	secret_free(request->code_verifier);
	memset(request, 0, sizeof(*request));
}

/*
** Exchange a validated authorization code within an optional transfer budget.
**
** Every form value is encoded independently before assembly.  This function
** only updates session after a 2xx token response passes token_response; it
** deliberately does not save auth.json because the interactive caller chooses
** the destination path after the exchange succeeds.
*/
static int
oauth_exchange_code_timeout(const char *code, const char *code_verifier,
    const char *redirect_uri, const char *client_id, const char *issuer,
    const char *token_url, int timeout_ms, oauth_cancel_callback cancel,
    void *cancel_argument, struct auth_session *session, char *error,
    size_t length)
{
	char		    *escaped_code;
	char		    *escaped_client;
	char		    *escaped_verifier;
	char		    *escaped_redirect;
	char		    *token_endpoint;
	struct buffer	     body;
	struct http_response response;
	int		     result;

	result = -1;
	buffer_init(&body);
	token_endpoint = NULL;
	escaped_code = http_form_encode(code);
	escaped_client = http_form_encode(
	    client_id == NULL ? DEFAULT_CLIENT_ID : client_id);
	escaped_verifier = http_form_encode(code_verifier);
	escaped_redirect = http_form_encode(redirect_uri);
	if (escaped_code == NULL || escaped_client == NULL ||
	    escaped_verifier == NULL || escaped_redirect == NULL) {
		set_error(error, length,
		    "could not encode OAuth token request");
		goto done;
	}
	if (buffer_append_string(&body,
		"grant_type=authorization_code&code=") == -1 ||
	    buffer_append_string(&body, escaped_code) == -1 ||
	    buffer_append_string(&body, "&redirect_uri=") == -1 ||
	    buffer_append_string(&body, escaped_redirect) == -1 ||
	    buffer_append_string(&body, "&client_id=") == -1 ||
	    buffer_append_string(&body, escaped_client) == -1 ||
	    buffer_append_string(&body, "&code_verifier=") == -1 ||
	    buffer_append_string(&body, escaped_verifier) == -1) {
		set_error(error, length, "could not build OAuth token request");
		goto done;
	}
	if (token_url == NULL) {
		token_endpoint = issuer_endpoint(issuer, "/oauth/token");
		if (token_endpoint == NULL) {
			set_error(error, length,
			    "could not allocate OAuth token endpoint");
			goto done;
		}
	}
	result = http_post_form_timeout(
	    token_url == NULL ? token_endpoint : token_url, body.data,
	    timeout_ms, cancel, cancel_argument, &response, error, length);
	if (result == -1)
		goto done;
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "token exchange failed with HTTP %ld",
		    response.status);
		result = -1;
	} else {
		result = token_response(response.body, response.body_length, 1,
		    session, error, length);
	}
	secret_clear(response.body, response.body_length);
	http_response_free(&response);

done:
	free(token_endpoint);
	secret_free(escaped_code);
	free(escaped_client);
	secret_free(escaped_verifier);
	free(escaped_redirect);
	secret_buffer_free(&body);
	return result;
}

/* Exchange a browser authorization code without imposing a new HTTP deadline. */
int
oauth_exchange_code(const char *code, const char *code_verifier,
    const char *redirect_uri, const char *client_id, const char *issuer,
    const char *token_url, oauth_cancel_callback cancel, void *cancel_argument,
    struct auth_session *session, char *error, size_t length)
{
	return oauth_exchange_code_timeout(code, code_verifier, redirect_uri,
	    client_id, issuer, token_url, 0, cancel, cancel_argument, session,
	    error, length);
}

/* Parse the decimal polling interval supplied by the device endpoint. */
static int
parse_device_interval(json_t *value, unsigned long *interval)
{
	const unsigned char *cursor;
	const char	    *text;
	json_int_t	     integer;
	size_t		     text_length;
	unsigned long	     digit;
	unsigned long	     parsed;

	if (json_is_integer(value)) {
		integer = json_integer_value(value);
		if (integer < 0 || (uintmax_t)integer > ULONG_MAX)
			return -1;
		*interval = (unsigned long)integer;
		return 0;
	}
	text = json_string_value(value);
	if (text == NULL || text[0] == '\0')
		return -1;
	text_length = json_string_length(value);
	if (text_length > 64 || strlen(text) != text_length)
		return -1;
	parsed = 0;
	cursor = (const unsigned char *)text;
	while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
	    *cursor == '\n' || *cursor == '\f' || *cursor == '\v')
		cursor++;
	if (*cursor == '\0')
		return -1;
	for (; *cursor >= '0' && *cursor <= '9'; cursor++) {
		digit = (unsigned long)(*cursor - '0');
		if (parsed > (ULONG_MAX - digit) / 10)
			return -1;
		parsed = parsed * 10 + digit;
	}
	while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
	    *cursor == '\n' || *cursor == '\f' || *cursor == '\v')
		cursor++;
	if (*cursor != '\0')
		return -1;
	*interval = parsed;
	return 0;
}

/* Accept only the printable alphabet used by OpenAI one-time device codes. */
static int
device_user_code_valid(const char *code)
{
	const unsigned char *cursor;

	for (cursor = (const unsigned char *)code; *cursor != '\0'; cursor++) {
		if ((*cursor >= 'A' && *cursor <= 'Z') ||
		    (*cursor >= 'a' && *cursor <= 'z') ||
		    (*cursor >= '0' && *cursor <= '9') || *cursor == '-')
			continue;
		return 0;
	}
	return 1;
}

/* Enforce the RFC 7636 verifier alphabet and length before token exchange. */
static int
device_verifier_valid(const char *verifier)
{
	const unsigned char *cursor;
	size_t		     verifier_length;

	verifier_length = strlen(verifier);
	if (verifier_length < 43 || verifier_length > 128)
		return 0;
	for (cursor = (const unsigned char *)verifier; *cursor != '\0';
	    cursor++) {
		if ((*cursor >= 'A' && *cursor <= 'Z') ||
		    (*cursor >= 'a' && *cursor <= 'z') ||
		    (*cursor >= '0' && *cursor <= '9') || *cursor == '-' ||
		    *cursor == '.' || *cursor == '_' || *cursor == '~')
			continue;
		return 0;
	}
	return 1;
}

/* Return the current monotonic clock in milliseconds for deadline arithmetic. */
static int64_t
monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return -1;
	if (now.tv_sec < 0 || (uintmax_t)now.tv_sec > INT64_MAX / 1000) {
		errno = EOVERFLOW;
		return -1;
	}
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Return a bounded number of milliseconds before an absolute deadline. */
static int
device_remaining_ms(int64_t deadline_ms)
{
	int64_t now;
	int64_t remaining;

	now = monotonic_ms();
	if (now == -1)
		return -1;
	remaining = deadline_ms - now;
	if (remaining <= 0)
		return 0;
	if (remaining > INT_MAX)
		return INT_MAX;
	return (int)remaining;
}

/* State shared by curl progress callbacks during one bounded device login. */
struct device_cancel_context {
	oauth_cancel_callback callback;
	void		     *argument;
	int64_t		      deadline_ms;
};

/* Stop a device transfer on signal cancellation or at its overall deadline. */
static int
device_cancelled(void *argument)
{
	struct device_cancel_context *context;
	int			      remaining;

	context = argument;
	if (context->callback != NULL &&
	    context->callback(context->argument) != 0)
		return 1;
	remaining = device_remaining_ms(context->deadline_ms);
	return remaining == -1 || remaining == 0;
}

/* Wait in short cancellable slices instead of sleeping for the whole
** interval. */
static int
device_wait(int64_t deadline_ms, unsigned long interval,
    oauth_cancel_callback callback, void *argument, char *error, size_t length)
{
	int64_t now;
	int64_t wait_deadline;
	int	remaining;
	int	wait_ms;
	int	slice;

	/* A zero server interval is legal; one second prevents a hot loop. */
	if (interval == 0)
		interval = 1;
	wait_ms = interval > (unsigned long)INT_MAX / 1000
	    ? INT_MAX
	    : (int)(interval * 1000);
	now = monotonic_ms();
	if (now == -1) {
		set_error(error, length,
		    "could not start device OAuth wait: %s", strerror(errno));
		return -1;
	}
	wait_deadline = now > INT64_MAX - wait_ms ? INT64_MAX : now + wait_ms;
	for (;;) {
		if (callback != NULL && callback(argument) != 0) {
			set_error(error, length,
			    "device OAuth login cancelled");
			return -1;
		}
		remaining = device_remaining_ms(deadline_ms);
		if (remaining == -1) {
			set_error(error, length,
			    "could not update device OAuth timeout: %s",
			    strerror(errno));
			return -1;
		}
		if (remaining == 0) {
			set_error(error, length,
			    "device OAuth login timed out waiting for approval");
			return -1;
		}
		now = monotonic_ms();
		if (now == -1) {
			set_error(error, length,
			    "could not update device OAuth wait: %s",
			    strerror(errno));
			return -1;
		}
		if (now >= wait_deadline)
			return 0;
		slice = wait_deadline - now > INT_MAX
		    ? INT_MAX
		    : (int)(wait_deadline - now);
		if (slice > remaining)
			slice = remaining;
		/* 100 ms slices make SIGTERM responsive even during a long wait. */
		if (slice > 100)
			slice = 100;
		if (poll(NULL, 0, slice) == -1 && errno != EINTR) {
			set_error(error, length,
			    "could not wait for device OAuth approval: %s",
			    strerror(errno));
			return -1;
		}
	}
}

/*
** Request the user code used by a headless device login.
**
** The endpoint deliberately returns a display URL rather than asking this
** process to launch a browser.  The short user code can therefore be entered
** on any other trusted device, while the device-auth id remains private to
** the subsequent polling exchange.
*/
int
oauth_device_code_request(const char *issuer, const char *client_id,
    int timeout_ms, oauth_cancel_callback cancel, void *cancel_argument,
    struct oauth_device_code *device, char *error, size_t length)
{
	char		    *body_text;
	char		    *endpoint;
	char		    *verification_url;
	char		    *device_auth_id;
	char		    *user_code;
	const char	    *text;
	json_t		    *body;
	json_t		    *field;
	json_t		    *root;
	struct http_response response;
	int64_t		     now;
	unsigned long	     interval;
	int		     remaining;
	int		     result;

	if (device == NULL || timeout_ms <= 0) {
		set_error(error, length,
		    "invalid device authorization timeout");
		return -1;
	}
	memset(device, 0, sizeof(*device));
	body = NULL;
	body_text = NULL;
	endpoint = NULL;
	verification_url = NULL;
	device_auth_id = NULL;
	user_code = NULL;
	now = monotonic_ms();
	if (now == -1) {
		set_error(error, length,
		    "could not start device OAuth timeout: %s",
		    strerror(errno));
		return -1;
	}
	if (now > INT64_MAX - timeout_ms) {
		set_error(error, length, "device OAuth timeout is too large");
		return -1;
	}
	device->deadline_ms = now + timeout_ms;
	body = json_pack("{s:s}", "client_id",
	    client_id == NULL ? DEFAULT_CLIENT_ID : client_id);
	if (body == NULL || (body_text = json_dump_compact(body)) == NULL) {
		json_decref(body);
		set_error(error, length,
		    "could not build device authorization request");
		return -1;
	}
	json_decref(body);
	endpoint = issuer_endpoint(issuer, "/api/accounts/deviceauth/usercode");
	if (endpoint == NULL) {
		set_error(error, length,
		    "could not allocate device authorization endpoint");
		goto fail;
	}
	remaining = device_remaining_ms(device->deadline_ms);
	if (remaining == -1) {
		set_error(error, length,
		    "could not update device OAuth timeout: %s",
		    strerror(errno));
		goto fail;
	}
	if (remaining == 0) {
		set_error(error, length, "device OAuth login timed out");
		goto fail;
	}
	result = http_post_json_timeout(endpoint, body_text, NULL, NULL, NULL,
	    remaining, cancel, cancel_argument, &response, error, length);
	if (result == -1)
		goto fail;
	if (response.status == 404) {
		set_error(error, length,
		    "device authorization is not enabled by this OpenAI account");
		secret_clear(response.body, response.body_length);
		http_response_free(&response);
		goto fail;
	}
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length,
		    "device authorization request failed with HTTP %ld",
		    response.status);
		secret_clear(response.body, response.body_length);
		http_response_free(&response);
		goto fail;
	}
	root = json_load_buffer_checked(response.body, response.body_length,
	    error, length);
	secret_clear(response.body, response.body_length);
	http_response_free(&response);
	if (root == NULL)
		goto fail;
	field = json_object_get(root, "device_auth_id");
	if (json_bounded_string(field, DEVICE_AUTH_ID_MAX, &text) == 0)
		device_auth_id = oaio_strdup(text);
	field = json_object_get(root, "user_code");
	if (field == NULL)
		field = json_object_get(root, "usercode");
	if (json_bounded_string(field, DEVICE_USER_CODE_MAX, &text) == 0)
		user_code = oaio_strdup(text);
	interval = 0;
	if (json_object_get(root, "interval") != NULL &&
	    parse_device_interval(json_object_get(root, "interval"),
		&interval) == -1) {
		set_error(error, length,
		    "device authorization response has an invalid interval");
		json_decref(root);
		goto fail;
	}
	json_decref(root);
	verification_url = issuer_endpoint(issuer, "/codex/device");
	if (device_auth_id == NULL || user_code == NULL ||
	    !device_user_code_valid(user_code) || verification_url == NULL) {
		set_error(error, length,
		    "device authorization response has invalid required fields");
		goto fail;
	}
	device->device_auth_id = device_auth_id;
	device_auth_id = NULL;
	device->user_code = user_code;
	user_code = NULL;
	device->verification_url = verification_url;
	verification_url = NULL;
	device->interval = interval;
	free(endpoint);
	secret_free(body_text);
	return 0;

fail:
	free(endpoint);
	secret_free(body_text);
	free(verification_url);
	secret_free(device_auth_id);
	secret_free(user_code);
	oauth_device_code_free(device);
	return -1;
}

/* Release a completed or partially parsed device authorization response. */
void
oauth_device_code_free(struct oauth_device_code *device)
{
	free(device->verification_url);
	secret_free(device->user_code);
	secret_free(device->device_auth_id);
	memset(device, 0, sizeof(*device));
}

/*
** Poll the device endpoint until approval, timeout, cancellation, or failure.
**
** HTTP 403 and 404 are the protocol's ordinary "still pending" responses.
** Every other non-2xx status is fatal.  On success the endpoint supplies a
** one-time authorization code and verifier, which are immediately exchanged
** through the normal OAuth token endpoint and never written to disk.
*/
int
oauth_device_code_poll(const char *issuer, const char *client_id,
    const char *token_url, const struct oauth_device_code *device,
    oauth_cancel_callback cancel, void *cancel_argument,
    struct auth_session *session, char *error, size_t length)
{
	struct device_cancel_context cancel_context;
	struct http_response	     response;
	char			    *body_text;
	char			    *endpoint;
	char			    *redirect_uri;
	const char		    *authorization_code;
	const char		    *code_challenge;
	const char		    *code_verifier;
	json_t			    *body;
	json_t			    *field;
	json_t			    *root;
	int			     remaining;
	int			     result;

	if (device == NULL || device->device_auth_id == NULL ||
	    device->user_code == NULL || device->deadline_ms <= 0) {
		set_error(error, length, "invalid device authorization state");
		return -1;
	}
	endpoint = issuer_endpoint(issuer, "/api/accounts/deviceauth/token");
	redirect_uri = issuer_endpoint(issuer, "/deviceauth/callback");
	if (endpoint == NULL || redirect_uri == NULL) {
		set_error(error, length,
		    "could not allocate device authorization endpoint");
		free(endpoint);
		free(redirect_uri);
		return -1;
	}
	cancel_context.callback = cancel;
	cancel_context.argument = cancel_argument;
	cancel_context.deadline_ms = device->deadline_ms;
	for (;;) {
		remaining = device_remaining_ms(device->deadline_ms);
		if (remaining == -1) {
			set_error(error, length,
			    "could not update device OAuth timeout: %s",
			    strerror(errno));
			result = -1;
			break;
		}
		if (remaining == 0) {
			set_error(error, length,
			    "device OAuth login timed out waiting for approval");
			result = -1;
			break;
		}
		body = json_pack("{s:s,s:s}", "device_auth_id",
		    device->device_auth_id, "user_code", device->user_code);
		body_text = body == NULL ? NULL : json_dump_compact(body);
		json_decref(body);
		if (body_text == NULL) {
			set_error(error, length,
			    "could not build device polling request");
			result = -1;
			break;
		}
		result = http_post_json_timeout(endpoint, body_text, NULL, NULL,
		    NULL, remaining, device_cancelled, &cancel_context,
		    &response, error, length);
		secret_free(body_text);
		if (result == -1) {
			if (cancel != NULL && cancel(cancel_argument) != 0)
				set_error(error, length,
				    "device OAuth login cancelled");
			else if (device_remaining_ms(device->deadline_ms) == 0)
				set_error(error, length,
				    "device OAuth login timed out waiting for approval");
			break;
		}
		if (response.status == 403 || response.status == 404) {
			secret_clear(response.body, response.body_length);
			http_response_free(&response);
			if (device_wait(device->deadline_ms, device->interval,
				cancel, cancel_argument, error, length) == -1) {
				result = -1;
				break;
			}
			continue;
		}
		if (response.status < 200 || response.status >= 300) {
			set_error(error, length,
			    "device authorization polling failed with HTTP %ld",
			    response.status);
			secret_clear(response.body, response.body_length);
			http_response_free(&response);
			result = -1;
			break;
		}
		root = json_load_buffer_checked(response.body,
		    response.body_length, error, length);
		secret_clear(response.body, response.body_length);
		http_response_free(&response);
		if (root == NULL) {
			result = -1;
			break;
		}
		authorization_code = NULL;
		code_challenge = NULL;
		code_verifier = NULL;
		field = json_object_get(root, "authorization_code");
		result = json_bounded_string(field, DEVICE_CODE_MAX,
		    &authorization_code);
		field = json_object_get(root, "code_challenge");
		if (result == 0)
			result =
			    json_bounded_string(field, 128, &code_challenge);
		field = json_object_get(root, "code_verifier");
		if (result == 0)
			result =
			    json_bounded_string(field, 128, &code_verifier);
		if (result == -1 || !device_verifier_valid(code_verifier)) {
			set_error(error, length,
			    "device authorization response has invalid PKCE fields");
			json_decref(root);
			result = -1;
			break;
		}
		/* Bind the one-time code to the verifier before sending it onward. */
		if (device_pkce_matches(code_verifier, code_challenge) == -1) {
			set_error(error, length,
			    "device authorization response has invalid PKCE");
			json_decref(root);
			result = -1;
			break;
		}
		remaining = device_remaining_ms(device->deadline_ms);
		if (remaining <= 0) {
			set_error(error, length,
			    "device OAuth login timed out waiting for approval");
			json_decref(root);
			result = -1;
			break;
		}
		result = oauth_exchange_code_timeout(authorization_code,
		    code_verifier, redirect_uri, client_id, issuer, token_url,
		    remaining, device_cancelled, &cancel_context, session,
		    error, length);
		if (result == -1) {
			if (cancel != NULL && cancel(cancel_argument) != 0)
				set_error(error, length,
				    "device OAuth login cancelled");
			else if (device_remaining_ms(device->deadline_ms) == 0)
				set_error(error, length,
				    "device OAuth login timed out waiting for approval");
		}
		json_decref(root);
		break;
	}
	free(endpoint);
	free(redirect_uri);
	return result;
}
