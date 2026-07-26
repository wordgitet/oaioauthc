#include "http.h"
#include "util.h"

#include <curl/curl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_RESPONSE_SIZE (64 * 1024 * 1024)

struct write_context {
	struct http_response	*response;
	struct buffer		*body;
	http_write_callback	 callback;
	void			*argument;
};

static void
set_error(char *error, size_t length, const char *format, ...)
{
	va_list	ap;

	if (error == NULL || length == 0)
		return;
	va_start(ap, format);
	(void)vsnprintf(error, length, format, ap);
	va_end(ap);
}

static int
append_header(struct curl_slist **headers, const char *value)
{
	struct curl_slist	*next;

	next = curl_slist_append(*headers, value);
	if (next == NULL)
		return -1;
	*headers = next;
	return 0;
}

static int
append_header_value(struct curl_slist **headers, const char *name,
    const char *value)
{
	struct buffer	header;
	int		result;

	buffer_init(&header);
	result = buffer_append_string(&header, name);
	if (result == 0)
		result = buffer_append_string(&header, value);
	if (result == 0)
		result = append_header(headers, header.data);
	buffer_free(&header);
	return result;
}

static size_t
write_callback(char *data, size_t size, size_t count, void *argument)
{
	struct write_context	*context;
	size_t			 length;

	context = argument;
	if (count != 0 && size > (size_t)-1 / count)
		return 0;
	length = size * count;
	if (context->callback != NULL && context->response->status >= 200 &&
	    context->response->status < 300)
		return context->callback(data, length, context->argument) == 0 ?
		    length : 0;
	if (context->body->len > MAX_RESPONSE_SIZE ||
	    length > MAX_RESPONSE_SIZE - context->body->len)
		return 0;
	if (buffer_append(context->body, data, length) == -1)
		return 0;
	return length;
}

static size_t
header_callback(char *data, size_t size, size_t count, void *argument)
{
	struct http_response	*response;
	char			*value;
	size_t			length;

	response = argument;
	length = size * count;
	if (length > 5 && strncasecmp(data, "HTTP/", 5) == 0) {
		char *space;

		space = memchr(data, ' ', length);
		if (space != NULL && data + length - space >= 4 &&
		    space[1] >= '0' && space[1] <= '9' &&
		    space[2] >= '0' && space[2] <= '9' &&
		    space[3] >= '0' && space[3] <= '9')
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

static int
request(const char *url, const char *method, const char *body,
    const char *authorization, const char *account_id, const char *extra_header,
    const char *content_type, http_write_callback callback, void *argument,
    struct http_response *response, char *error, size_t error_length)
{
	CURL			*curl;
	CURLcode		code;
	struct curl_slist	*headers;
	struct buffer		response_body;
	struct write_context	context;

	memset(response, 0, sizeof(*response));
	buffer_init(&response_body);
	context.response = response;
	context.body = &response_body;
	context.callback = callback;
	context.argument = argument;
	headers = NULL;
	curl = curl_easy_init();
	if (curl == NULL) {
		set_error(error, error_length, "could not initialize libcurl");
		return -1;
	}
	if (append_header(&headers, "Accept: application/json") == -1 ||
	    (body != NULL && append_header(&headers, content_type == NULL ?
	    "Content-Type: application/json" : content_type) == -1) ||
	    (authorization != NULL && append_header_value(&headers,
	    "Authorization: Bearer ", authorization) == -1) ||
	    (account_id != NULL && append_header_value(&headers,
	    "chatgpt-account-id: ", account_id) == -1) ||
	    (extra_header != NULL &&
	    append_header(&headers, extra_header) == -1)) {
		set_error(error, error_length, "could not allocate HTTP headers");
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		return -1;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "oaioauthc/0.1.0");
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 120L);
	if (body != NULL)
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	code = curl_easy_perform(curl);
	if (code != CURLE_OK) {
		set_error(error, error_length, "upstream request failed: %s",
		    curl_easy_strerror(code));
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		buffer_free(&response_body);
		http_response_free(response);
		return -1;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status);
	response->body = buffer_steal(&response_body);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return 0;
}

int
http_post_json(const char *url, const char *body, const char *authorization,
    const char *account_id, const char *extra_header,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, authorization, account_id, extra_header,
	    NULL, NULL, NULL, response, error, error_length);
}

int
http_post_json_stream(const char *url, const char *body,
    const char *authorization, const char *account_id,
    const char *extra_header, http_write_callback callback, void *argument,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, authorization, account_id, extra_header,
	    NULL, callback, argument, response, error, error_length);
}

int
http_post_form(const char *url, const char *body,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "POST", body, NULL, NULL, NULL,
	    "Content-Type: application/x-www-form-urlencoded", NULL, NULL,
	    response, error, error_length);
}

int
http_get(const char *url, const char *authorization, const char *account_id,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "GET", NULL, authorization, account_id, NULL, NULL,
	    NULL, NULL, response, error, error_length);
}

void
http_response_free(struct http_response *response)
{
	free(response->body);
	free(response->content_type);
	memset(response, 0, sizeof(*response));
}

char
*http_form_encode(const char *value)
{
	CURL	*curl;
	char	*escaped;
	char	*copy;

	curl = curl_easy_init();
	if (curl == NULL)
		return NULL;
	escaped = curl_easy_escape(curl, value, 0);
	copy = escaped == NULL ? NULL : oaio_strdup(escaped);
	curl_free(escaped);
	curl_easy_cleanup(curl);
	return copy;
}
