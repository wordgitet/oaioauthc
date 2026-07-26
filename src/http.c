#include "http.h"
#include "util.h"

#include <curl/curl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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

static size_t
write_callback(char *data, size_t size, size_t count, void *argument)
{
	struct buffer	*body;
	size_t		length;

	body = argument;
	length = size * count;
	if (buffer_append(body, data, length) == -1)
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
    const char *content_type, struct http_response *response, char *error,
    size_t error_length)
{
	CURL			*curl;
	CURLcode		code;
	struct curl_slist	*headers;
	struct buffer		response_body;
	char			header[4096];

	memset(response, 0, sizeof(*response));
	buffer_init(&response_body);
	headers = NULL;
	curl = curl_easy_init();
	if (curl == NULL) {
		set_error(error, error_length, "could not initialize libcurl");
		return -1;
	}
	headers = curl_slist_append(headers, "Accept: application/json");
	if (body != NULL)
		headers = curl_slist_append(headers, content_type == NULL ?
		    "Content-Type: application/json" : content_type);
	if (authorization != NULL) {
		(void)snprintf(header, sizeof(header), "Authorization: Bearer %s",
		    authorization);
		headers = curl_slist_append(headers, header);
	}
	if (account_id != NULL) {
		(void)snprintf(header, sizeof(header), "chatgpt-account-id: %s",
		    account_id);
		headers = curl_slist_append(headers, header);
	}
	if (extra_header != NULL)
		headers = curl_slist_append(headers, extra_header);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "oaioauthc/0.1.0");
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
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
	    NULL, response, error, error_length);
}

int
http_post_form(const char *url, const char *body, struct http_response *response,
    char *error, size_t error_length)
{
	return request(url, "POST", body, NULL, NULL, NULL,
	    "Content-Type: application/x-www-form-urlencoded", response, error,
	    error_length);
}

int
http_get(const char *url, const char *authorization, const char *account_id,
    struct http_response *response, char *error, size_t error_length)
{
	return request(url, "GET", NULL, authorization, account_id, NULL, NULL,
	    response, error, error_length);
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
