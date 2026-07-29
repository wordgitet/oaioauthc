/*
** Small libcurl wrapper for the OAuth and Codex HTTP exchanges.
**
** The interface has two response modes.  Ordinary calls retain a bounded copy
** of the complete response body.  Streaming calls forward only successful
** response bytes to a callback, while still buffering non-2xx bodies so the
** proxy can return a useful upstream error.  A callback failure stops curl
** and is reported to the caller as a transport failure.
**
** This is the single place that adds the bearer authorization and
** chatgpt-account-id headers used by Codex.  Callers supply already encoded
** request bodies and own endpoint semantics; this module owns libcurl lists,
** temporary buffers, and response allocations until they are handed back.
*/

#include <curl/curl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "http.h"
#include "util.h"

#define MAX_RESPONSE_SIZE (64 * 1024 * 1024)

/*
** Per-transfer callback state.
**
** body receives buffered content.  callback is used only for successful
** response bodies; keeping error bodies in body lets higher layers preserve
** upstream status and diagnostics.
*/
struct write_context {
	struct http_response *response;
	struct buffer	     *body;
	http_write_callback   callback;
	void		     *argument;
};

/* Per-transfer cancellation callback passed through libcurl progress checks. */
struct cancel_context {
	http_cancel_callback callback;
	void		    *argument;
};

/* Populate an optional caller diagnostic buffer without allocating. */
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

/* Append a header string without discarding the old list on failure. */
static int
append_header(struct curl_slist **headers, const char *value)
{
	struct curl_slist *next;

	next = curl_slist_append(*headers, value);
	if (next == NULL)
		return -1;
	*headers = next;
	return 0;
}

/* Build "name + value" as one curl header and release the temporary buffer. */
static int
append_header_value(struct curl_slist **headers, const char *name,
    const char *value)
{
	struct buffer header;
	int	      result;

	buffer_init(&header);
	result = buffer_append_string(&header, name);
	if (result == 0)
		result = buffer_append_string(&header, value);
	if (result == 0)
		result = append_header(headers, header.data);
	buffer_free(&header);
	return (result);
}

/*
** Consume one libcurl body fragment.
**
** Returning fewer bytes tells libcurl to stop.  Successful streams go directly
** to callback; all other content is appended subject to MAX_RESPONSE_SIZE.
*/
static size_t
write_callback(char *data, size_t size, size_t count, void *argument)
{
	struct write_context *context;
	size_t		      length;

	context = argument;
	if (count != 0 && size > (size_t)-1 / count)
		return 0;
	length = size * count;
	/* Stream only successful bodies; preserve upstream errors for the caller. */
	if (context->callback != NULL && context->response->status >= 200 &&
	    context->response->status < 300)
		return context->callback(data, length, context->argument) == 0
		    ? length
		    : 0;
	if (context->body->len > MAX_RESPONSE_SIZE ||
	    length > MAX_RESPONSE_SIZE - context->body->len)
		return 0;
	if (buffer_append(context->body, data, length) == -1)
		return 0;
	return length;
}

/*
** Record status and Content-Type while curl processes headers.
**
** Multiple response blocks (for redirects or 100 Continue) are tolerated by
** replacing values when a new HTTP status line arrives.
*/
static size_t
header_callback(char *data, size_t size, size_t count, void *argument)
{
	struct http_response *response;
	char		     *value;
	size_t		      length;

	response = argument;
	if (count != 0 && size > (size_t)-1 / count)
		return 0;
	length = size * count;
	if (length > 5 && strncasecmp(data, "HTTP/", 5) == 0) {
		char *space;

		space = memchr(data, ' ', length);
		if (space != NULL && data + length - space >= 4 &&
		    space[1] >= '0' && space[1] <= '9' && space[2] >= '0' &&
		    space[2] <= '9' && space[3] >= '0' && space[3] <= '9')
			response->status = (space[1] - '0') * 100 +
			    (space[2] - '0') * 10 + space[3] - '0';
		free(response->content_type);
		response->content_type = NULL;
		return length;
	}
	if (length < 14 || strncasecmp(data, "Content-Type:", 13) != 0)
		return length;
	value = malloc(length - 12);
	if (value == NULL)
		return 0;
	memcpy(value, data + 13, length - 13);
	value[length - 13] = '\0';
	while (value[0] == ' ' || value[0] == '\t')
		memmove(value, value + 1, strlen(value));
	value[strcspn(value, "\r\n")] = '\0';
	free(response->content_type);
	response->content_type = value;
	return length;
}

/* Abort a synchronous transfer after the caller records cancellation. */
static int
transfer_progress(void *argument, curl_off_t download_total,
    curl_off_t download_now, curl_off_t upload_total, curl_off_t upload_now)
{
	struct cancel_context *context;

	(void)download_total;
	(void)download_now;
	(void)upload_total;
	(void)upload_now;
	context = argument;
	return context->callback(context->argument) != 0;
}

/*
** Perform one synchronous HTTP exchange.
**
** url, method, and body are borrowed.  On success response owns body and
** content_type until http_response_free.  On every failure this function
** frees curl state and partial response data, then returns -1 with error set.
** No redirect policy is enabled here: OAuth and Codex endpoint choices remain
** explicit to their callers.
*/
static int
request(const char *url, const char *method, const char *body,
    const char *authorization, const char *account_id, const char *extra_header,
    const char *content_type, http_write_callback callback, void *argument,
    int timeout_ms, http_cancel_callback cancel, void *cancel_argument,
    struct http_response *response, char *error, size_t error_length)
{
	CURL		     *curl;
	CURLcode	      code;
	struct cancel_context cancel_context;
	struct curl_slist    *headers;
	struct buffer	      response_body;
	struct write_context  context;
	int		      result;

	/*
	 * response is reset before work begins.  On success its body is owned by
	 * the caller; on failure this function releases every partial allocation.
	 */
	memset(response, 0, sizeof(*response));
	buffer_init(&response_body);
	context.response = response;
	context.body = &response_body;
	context.callback = callback;
	context.argument = argument;
	cancel_context.callback = cancel;
	cancel_context.argument = cancel_argument;
	headers = NULL;
	result = -1;
	curl = curl_easy_init();
	if (curl == NULL) {
		set_error(error, error_length, "could not initialize libcurl");
		return -1;
	}
	if (append_header(&headers, "Accept: application/json") == -1 ||
	    (body != NULL &&
		append_header(&headers,
		    content_type == NULL ? "Content-Type: application/json"
					 : content_type) == -1) ||
	    (authorization != NULL &&
		append_header_value(&headers, "Authorization: Bearer ",
		    authorization) == -1) ||
	    (account_id != NULL &&
		append_header_value(&headers,
		    "chatgpt-account-id: ", account_id) == -1) ||
	    (extra_header != NULL &&
		append_header(&headers, extra_header) == -1)) {
		set_error(error, error_length,
		    "could not allocate HTTP headers");
		goto cleanup;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "oaioauthc/0.2.1");
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	code = curl_easy_setopt(curl, CURLOPT_SSLVERSION,
	    CURL_SSLVERSION_TLSv1_2);
	if (code != CURLE_OK) {
		set_error(error, error_length,
		    "could not require TLS 1.2 for upstream requests: %s",
		    curl_easy_strerror(code));
		goto cleanup;
	}
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 120L);
	if (timeout_ms > 0)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
	if (cancel != NULL) {
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,
		    transfer_progress);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &cancel_context);
	}
	if (body != NULL)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	if (body != NULL)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
		    (curl_off_t)strlen(body));
	code = curl_easy_perform(curl);
	if (code != CURLE_OK) {
		set_error(error, error_length, "upstream request failed: %s",
		    curl_easy_strerror(code));
		goto cleanup;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status);
	response->body_length = response_body.len;
	response->body = buffer_steal(&response_body);
	if (response->body == NULL) {
		set_error(error, error_length,
		    "could not allocate upstream response");
		goto cleanup;
	}
	result = 0;

cleanup:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	if (result != 0) {
		buffer_free(&response_body);
		http_response_free(response);
	}
	return result;
}

/* POST JSON with optional Codex auth/account/feature headers. */
int
http_post_json(const char *url, const char *body, const char *authorization,
    const char *account_id, const char *extra_header,
    http_cancel_callback cancel, void *cancel_argument,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, authorization, account_id,
	    extra_header, NULL, NULL, NULL, 0, cancel, cancel_argument,
	    response, error, error_length);
}

/* POST JSON with a strict whole-transfer timeout and optional cancellation. */
int
http_post_json_timeout(const char *url, const char *body,
    const char *authorization, const char *account_id, const char *extra_header,
    int timeout_ms, http_cancel_callback cancel, void *cancel_argument,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, authorization, account_id,
	    extra_header, NULL, NULL, NULL, timeout_ms, cancel, cancel_argument,
	    response, error, error_length);
}

/* POST JSON and deliver successful response fragments to callback. */
int
http_post_json_stream(const char *url, const char *body,
    const char *authorization, const char *account_id, const char *extra_header,
    http_write_callback callback, void *argument,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, authorization, account_id,
	    extra_header, NULL, callback, argument, 0, NULL, NULL, response,
	    error, error_length);
}

/* POST an OAuth URL-encoded body without Codex authorization headers. */
int
http_post_form(const char *url, const char *body, http_cancel_callback cancel,
    void *cancel_argument, struct http_response *response, char *error,
    size_t error_length)
{
	return request(url, "POST", body, NULL, NULL, NULL,
	    "Content-Type: application/x-www-form-urlencoded", NULL, NULL, 0,
	    cancel, cancel_argument, response, error, error_length);
}

/* POST an OAuth form with a strict whole-transfer timeout. */
int
http_post_form_timeout(const char *url, const char *body, int timeout_ms,
    http_cancel_callback cancel, void *cancel_argument,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, NULL, NULL, NULL,
	    "Content-Type: application/x-www-form-urlencoded", NULL, NULL,
	    timeout_ms, cancel, cancel_argument, response, error, error_length);
}

/* GET an authenticated Codex resource into a bounded buffered response. */
int
http_get(const char *url, const char *authorization, const char *account_id,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "GET", NULL, authorization, account_id, NULL, NULL,
	    NULL, NULL, 0, NULL, NULL, response, error, error_length);
}

/* Release both response allocations and reset the structure for safe reuse. */
void
http_response_free(struct http_response *response)
{
	free(response->body);
	free(response->content_type);
	memset(response, 0, sizeof(*response));
}

/*
** Form-encode one UTF-8 byte string with libcurl's escaping rules.
**
** curl_easy_escape returns a curl allocation, so copy it into the program's
** ordinary malloc ownership domain before cleaning up the curl handle.
*/
char *
http_form_encode(const char *value)
{
	CURL *curl;
	char *escaped;
	char *copy;

	curl = curl_easy_init();
	if (curl == NULL)
		return NULL;
	escaped = curl_easy_escape(curl, value, 0);
	copy = escaped == NULL ? NULL : oaio_strdup(escaped);
	curl_free(escaped);
	curl_easy_cleanup(curl);
	return copy;
}
