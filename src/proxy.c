#include "proxy.h"
#include "auth.h"
#include "http.h"
#include "images.h"
#include "json.h"
#include "sse.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_BASE_URL "https://chatgpt.com/backend-api/codex"
#define CODEX_REGISTRY_URL \
	"https://registry.npmjs.org/@openai/codex/latest"
#define MAX_REQUEST_SIZE ((size_t)8 * 1024 * 1024)
#define MAX_HEADER_SIZE ((size_t)64 * 1024)
#define CLIENT_TIMEOUT 30
#define MAX_WORKERS 32

struct request {
	char	*method;
	char	*path;
	char	*content_type;
	char	*body;
	size_t	 body_length;
};

struct model_catalog {
	json_t	*root;
	char	*account_id;
	time_t	expires;
};

struct stream_client {
	int	fd;
	int	started;
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

static void
child_exited(int signal_number)
{
	(void)signal_number;
}

static void
set_client_timeout(int fd)
{
	struct timeval	timeout;

	timeout.tv_sec = CLIENT_TIMEOUT;
	timeout.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
	    sizeof(timeout));
}

static int
send_response(int fd, int status, const char *content_type, const char *body)
{
	char	headers[512];
	int	length;

	length = snprintf(headers, sizeof(headers),
	    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
	    "Connection: close\r\n\r\n", status,
	    status >= 200 && status < 300 ? "OK" : "Error", content_type,
	    strlen(body));
	if (length < 0 || (size_t)length >= sizeof(headers))
		return -1;
	return write_all(fd, headers, (size_t)length) == -1 ? -1 :
	    write_all(fd, body, strlen(body));
}

static int
send_stream_headers(struct stream_client *client)
{
	static const char headers[] =
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: text/event-stream; charset=utf-8\r\n"
	    "Cache-Control: no-cache\r\n"
	    "Connection: close\r\n\r\n";

	if (client->started)
		return 0;
	if (write_all(client->fd, headers, sizeof(headers) - 1) == -1)
		return -1;
	client->started = 1;
	return 0;
}

static int
write_stream(const void *data, size_t length, void *argument)
{
	struct stream_client	*client;

	client = argument;
	if (send_stream_headers(client) == -1)
		return -1;
	return write_all(client->fd, data, length);
}

static int
write_chat_stream(const void *data, size_t length, void *argument)
{
	return sse_chat_stream_feed(argument, data, length);
}

static int
send_json(int fd, int status, json_t *body)
{
	char	*text;
	int	result;

	text = json_dump_compact(body);
	if (text == NULL)
		return -1;
	result = send_response(fd, status, "application/json; charset=utf-8", text);
	free(text);
	return result;
}

static int
send_error(int fd, int status, const char *message, const char *type)
{
	json_t	*body;
	int	result;

	body = json_pack("{s:{s:s,s:s}}", "error", "message", message,
	    "type", type);
	result = send_json(fd, status, body);
	json_decref(body);
	return result;
}

static int
debug_sensitive_key(const char *key)
{
	static const char *sensitive[] = {
		"access_token",
		"api_key",
		"authorization",
		"encrypted_content",
		"refresh_token"
	};
	size_t	index;

	for (index = 0; index < sizeof(sensitive) / sizeof(sensitive[0]);
	    index++) {
		if (strcasecmp(key, sensitive[index]) == 0)
			return 1;
	}
	return 0;
}

static json_t *
debug_json_copy(json_t *value)
{
	const char	*key;
	const char	*string;
	json_t		*child;
	json_t		*copy;
	json_t		*result;
	size_t		 index;
	char		 redacted[96];

	if (json_is_string(value)) {
		string = json_string_value(value);
		if (strncmp(string, "data:", 5) == 0 &&
		    strstr(string, ";base64,") != NULL) {
			(void)snprintf(redacted, sizeof(redacted),
			    "[redacted data URL: %zu characters]", strlen(string));
			return json_string(redacted);
		}
		return json_stringn(string, json_string_length(value));
	}
	if (json_is_array(value)) {
		result = json_array();
		if (result == NULL)
			return NULL;
		json_array_foreach(value, index, child) {
			copy = debug_json_copy(child);
			if (copy == NULL ||
			    json_array_append_new(result, copy) == -1) {
				json_decref(result);
				return NULL;
			}
		}
		return result;
	}
	if (json_is_object(value)) {
		result = json_object();
		if (result == NULL)
			return NULL;
		json_object_foreach(value, key, child) {
			copy = debug_sensitive_key(key) ?
			    json_string("[redacted]") : debug_json_copy(child);
			if (copy == NULL ||
			    json_object_set_new(result, key, copy) == -1) {
				json_decref(result);
				return NULL;
			}
		}
		return result;
	}
	return json_deep_copy(value);
}

static void
debug_json_write(const char *label, const char *text)
{
	struct buffer	line;
	char		prefix[128];
	int		length;

	length = snprintf(prefix, sizeof(prefix), "[debug-json pid=%ld] %s: ",
	    (long)getpid(), label);
	if (length < 0 || (size_t)length >= sizeof(prefix))
		return;
	buffer_init(&line);
	if (buffer_append(&line, prefix, (size_t)length) == -1 ||
	    buffer_append_string(&line, text) == -1 ||
	    buffer_append_string(&line, "\n") == -1) {
		buffer_free(&line);
		return;
	}
	(void)write_all(STDERR_FILENO, line.data, line.len);
	buffer_free(&line);
}

static void
debug_json_value(const struct proxy_options *options, const char *label,
    json_t *value)
{
	json_t	*copy;
	char	*text;
	size_t	 flags;

	if (options->debug_json == debug_json_disabled)
		return;
	copy = debug_json_copy(value);
	flags = options->debug_json == debug_json_pretty ?
	    JSON_INDENT(2) : JSON_COMPACT;
	text = copy == NULL ? NULL : json_dumps(copy, flags);
	json_decref(copy);
	if (text == NULL) {
		debug_json_write(label, "[could not encode JSON]");
		return;
	}
	debug_json_write(label, text);
	free(text);
}

static void
debug_json_text(const struct proxy_options *options, const char *label,
    const char *text)
{
	json_t	*value;

	if (options->debug_json == debug_json_disabled)
		return;
	value = json_loads(text, 0, NULL);
	if (value == NULL) {
		debug_json_write(label, "[invalid JSON]");
		return;
	}
	debug_json_value(options, label, value);
	json_decref(value);
}

static void
request_free(struct request *request)
{
	free(request->method);
	free(request->path);
	free(request->content_type);
	free(request->body);
	memset(request, 0, sizeof(*request));
}

static int
read_more(int fd, struct buffer *buffer, size_t limit)
{
	char	chunk[4096];
	ssize_t	count;

	do {
		count = read(fd, chunk, sizeof(chunk));
	} while (count == -1 && errno == EINTR);
	if (count <= 0 || (size_t)count > limit ||
	    buffer->len > limit - (size_t)count)
		return -1;
	return buffer_append(buffer, chunk, (size_t)count);
}

static int
parse_content_length(const char *value, size_t *length)
{
	char			*end;
	unsigned long long	number;

	while (*value == ' ' || *value == '\t')
		value++;
	if (*value < '0' || *value > '9')
		return -1;
	errno = 0;
	number = strtoull(value, &end, 10);
	if (errno != 0 || number > (unsigned long long)(size_t)-1)
		return -1;
	while (*end == ' ' || *end == '\t')
		end++;
	if (*end != '\0')
		return -1;
	*length = (size_t)number;
	return 0;
}

static int
read_chunked_body(int fd, struct buffer *raw, size_t cursor,
    size_t body_limit, size_t raw_limit, struct request *request)
{
	struct buffer	body;
	char		*end;
	char		*line_end;
	char		number[32];
	unsigned long long	chunk_length;
	size_t		line_length;

	buffer_init(&body);
	for (;;) {
		while ((line_end = strstr(raw->data + cursor, "\r\n")) == NULL) {
			if (read_more(fd, raw, raw_limit) == -1)
				goto fail;
		}
		line_length = (size_t)(line_end - (raw->data + cursor));
		if (line_length == 0 || line_length >= sizeof(number))
			goto fail;
		memcpy(number, raw->data + cursor, line_length);
		number[line_length] = '\0';
		errno = 0;
		chunk_length = strtoull(number, &end, 16);
		while (*end == ' ' || *end == '\t')
			end++;
		if (errno != 0 || end == number ||
		    (*end != '\0' && *end != ';') ||
		    chunk_length > body_limit - body.len)
			goto fail;
		cursor = (size_t)(line_end - raw->data) + 2;
		if (chunk_length == 0) {
			for (;;) {
				if (raw->len - cursor >= 2 &&
				    raw->data[cursor] == '\r' &&
				    raw->data[cursor + 1] == '\n')
					break;
				if (strstr(raw->data + cursor,
				    "\r\n\r\n") != NULL)
					break;
				if (read_more(fd, raw, raw_limit) == -1)
					goto fail;
			}
			break;
		}
		while (raw->len - cursor < (size_t)chunk_length + 2) {
			if (read_more(fd, raw, raw_limit) == -1)
				goto fail;
		}
		if (raw->data[cursor + (size_t)chunk_length] != '\r' ||
		    raw->data[cursor + (size_t)chunk_length + 1] != '\n')
			goto fail;
		if (buffer_append(&body, raw->data + cursor,
		    (size_t)chunk_length) == -1)
			goto fail;
		cursor += (size_t)chunk_length + 2;
	}
	request->body_length = body.len;
	request->body = buffer_steal(&body);
	return request->body == NULL ? -1 : 0;

fail:
	buffer_free(&body);
	return -1;
}

static int
read_request(int fd, struct request *request)
{
	struct buffer	buffer;
	char		*header_end;
	char		*header;
	char		*line_end;
	char		*line;
	char		*method;
	char		*path;
	char		*version;
	char		*colon;
	char		*query;
	char		*value_end;
	char		*value;
	size_t		body_offset;
	size_t		length;
	size_t		parsed_length;
	size_t		body_limit;
	size_t		raw_limit;
	size_t		copied;
	ssize_t		count;
	int		has_content_length;
	int		expect_continue;
	int		chunked;
	int		last_header;

	memset(request, 0, sizeof(*request));
	buffer_init(&buffer);
	while ((header_end = buffer.data == NULL ? NULL : strstr(buffer.data,
	    "\r\n\r\n")) == NULL) {
		if (read_more(fd, &buffer, MAX_HEADER_SIZE) == -1) {
			buffer_free(&buffer);
			return -1;
		}
	}
	body_offset = (size_t)(header_end - buffer.data) + 4;
	*header_end = '\0';
	line = buffer.data;
	line_end = strstr(line, "\r\n");
	if (line_end == NULL) {
		buffer_free(&buffer);
		return -1;
	}
	*line_end = '\0';
	method = strtok(line, " ");
	path = strtok(NULL, " ");
	version = strtok(NULL, " ");
	if (method == NULL || path == NULL || version == NULL ||
	    strcmp(version, "HTTP/1.1") != 0) {
		buffer_free(&buffer);
		return -1;
	}
	request->method = oaio_strdup(method);
	request->path = oaio_strdup(path);
	if (request->method == NULL || request->path == NULL) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	query = strchr(request->path, '?');
	if (query != NULL)
		*query = '\0';
	length = 0;
	has_content_length = 0;
	expect_continue = 0;
	chunked = 0;
	header = line_end + 2;
	while (*header != '\0') {
		line_end = strstr(header, "\r\n");
		if (line_end == NULL) {
			line_end = header + strlen(header);
			last_header = 1;
		} else {
			last_header = 0;
			*line_end = '\0';
		}
		colon = strchr(header, ':');
		if (colon == NULL || colon == header) {
			request_free(request);
			buffer_free(&buffer);
			return -1;
		}
		*colon = '\0';
		value = colon + 1;
		while (*value == ' ' || *value == '\t')
			value++;
		value_end = value + strlen(value);
		while (value_end > value &&
		    (value_end[-1] == ' ' || value_end[-1] == '\t'))
			*--value_end = '\0';
		if (strcasecmp(header, "Content-Length") == 0) {
			if (parse_content_length(value, &parsed_length) == -1 ||
			    (has_content_length && parsed_length != length)) {
				request_free(request);
				buffer_free(&buffer);
				return -1;
			}
			length = parsed_length;
			has_content_length = 1;
		} else if (strcasecmp(header, "Transfer-Encoding") == 0) {
			chunked = strcasecmp(value, "chunked") == 0;
			if (!chunked) {
				request_free(request);
				buffer_free(&buffer);
				return -1;
			}
		} else if (strcasecmp(header, "Expect") == 0) {
			expect_continue = strcasecmp(value, "100-continue") == 0;
			if (!expect_continue) {
				request_free(request);
				buffer_free(&buffer);
				return -1;
			}
		} else if (strcasecmp(header, "Content-Type") == 0) {
			if (request->content_type != NULL &&
			    strcasecmp(request->content_type, value) != 0) {
				request_free(request);
				buffer_free(&buffer);
				return -1;
			}
			if (request->content_type == NULL) {
				request->content_type = oaio_strdup(value);
				if (request->content_type == NULL) {
					request_free(request);
					buffer_free(&buffer);
					return -1;
				}
			}
		}
		if (last_header)
			break;
		header = line_end + 2;
	}
	if (chunked && has_content_length) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	body_limit = strcmp(request->path, "/v1/images/edits") == 0 ?
	    IMAGE_MAX_EDIT_BODY : MAX_REQUEST_SIZE;
	if (length > body_limit || body_offset > (size_t)-1 - body_limit) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	raw_limit = body_offset + body_limit;
	if (expect_continue &&
	    write_all(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25) == -1) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	if (chunked) {
		if (read_chunked_body(fd, &buffer, body_offset, body_limit,
		    raw_limit, request) == -1) {
			request_free(request);
			buffer_free(&buffer);
			return -1;
		}
		buffer_free(&buffer);
		return 0;
	}
	request->body = malloc(length + 1);
	if (request->body == NULL) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	copied = buffer.len - body_offset;
	if (copied > length)
		copied = length;
	memcpy(request->body, buffer.data + body_offset, copied);
	while (copied < length) {
		do {
			count = read(fd, request->body + copied, length - copied);
		} while (count == -1 && errno == EINTR);
		if (count <= 0) {
			request_free(request);
			buffer_free(&buffer);
			return -1;
		}
		copied += (size_t)count;
	}
	request->body[length] = '\0';
	request->body_length = length;
	buffer_free(&buffer);
	return 0;
}

static char
*upstream_url(const struct proxy_options *options, const char *suffix)
{
	struct buffer	buffer;
	const char	*base;

	base = options->base_url == NULL ? DEFAULT_BASE_URL : options->base_url;
	buffer_init(&buffer);
	if (buffer_append_string(&buffer, base) == -1 ||
	    (base[strlen(base) - 1] == '/' ? 0 :
	    buffer_append_string(&buffer, "/")) == -1 ||
	    buffer_append_string(&buffer, suffix) == -1) {
		buffer_free(&buffer);
		return NULL;
	}
	return buffer_steal(&buffer);
}

static int
valid_codex_version(const char *version)
{
	int	segment;

	if (version == NULL)
		return 0;
	for (segment = 0; segment < 3; segment++) {
		if (!isdigit((unsigned char)*version))
			return 0;
		while (isdigit((unsigned char)*version))
			version++;
		if (segment < 2) {
			if (*version != '.')
				return 0;
			version++;
		}
	}
	return *version == '\0';
}

static char *
resolve_codex_version(const struct proxy_options *options, char *error,
    size_t length)
{
	struct http_response	response;
	const char		*version;
	char			*result;
	json_t			*root;

	if (valid_codex_version(options->codex_version))
		return oaio_strdup(options->codex_version);
	if (http_get(CODEX_REGISTRY_URL, NULL, NULL, &response, error,
	    length) == -1)
		return NULL;
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "Codex version lookup failed with HTTP %ld",
		    response.status);
		http_response_free(&response);
		return NULL;
	}
	root = json_loads(response.body, 0, NULL);
	http_response_free(&response);
	version = json_string_value(json_object_get(root, "version"));
	if (!valid_codex_version(version)) {
		json_decref(root);
		set_error(error, length,
		    "Codex version registry returned an invalid version");
		return NULL;
	}
	result = oaio_strdup(version);
	json_decref(root);
	if (result == NULL)
		set_error(error, length, "could not allocate Codex version");
	return result;
}

static void
model_catalog_free(struct model_catalog *catalog)
{
	json_decref(catalog->root);
	free(catalog->account_id);
	memset(catalog, 0, sizeof(*catalog));
}

static int
load_model_catalog(const struct proxy_options *options,
    const struct auth_session *session, struct model_catalog *catalog,
    char *error, size_t length)
{
	struct buffer		full;
	struct http_response	response;
	char			*url;
	char			*version;
	json_t			*root;
	json_t			*models;
	json_t			*model;
	size_t			index;
	int			valid_models;

	if (catalog->root != NULL && catalog->account_id != NULL &&
	    strcmp(catalog->account_id, session->account_id) == 0 &&
	    catalog->expires > time(NULL))
		return 0;
	url = upstream_url(options, "models?client_version=");
	version = http_form_encode(options->codex_version);
	if (url == NULL || version == NULL) {
		free(url);
		free(version);
		set_error(error, length, "out of memory");
		return -1;
	}
	buffer_init(&full);
	if (buffer_append_string(&full, url) == -1 ||
	    buffer_append_string(&full, version) == -1) {
		free(url);
		free(version);
		buffer_free(&full);
		set_error(error, length, "out of memory");
		return -1;
	}
	free(url);
	free(version);
	url = buffer_steal(&full);
	if (url == NULL)
		return -1;
	if (http_get(url, session->access_token, session->account_id, &response,
	    error, length) == -1) {
		free(url);
		return -1;
	}
	free(url);
	if (response.status < 200 || response.status >= 300) {
		set_error(error, length, "failed to load models from Codex");
		http_response_free(&response);
		return -1;
	}
	root = json_load_string_checked(response.body, error, length);
	http_response_free(&response);
	models = json_object_get(root, "models");
	valid_models = 0;
	if (json_is_array(models)) {
		json_array_foreach(models, index, model) {
			if (json_is_string(json_object_get(model, "slug")))
				valid_models++;
		}
	}
	if (!json_is_object(root) || !json_is_array(models) ||
	    valid_models == 0) {
		json_decref(root);
		set_error(error, length,
		    "Codex returned an empty or malformed models response");
		return -1;
	}
	model_catalog_free(catalog);
	catalog->account_id = oaio_strdup(session->account_id);
	if (catalog->account_id == NULL) {
		json_decref(root);
		return -1;
	}
	catalog->root = root;
	catalog->expires = time(NULL) + 300;
	return 0;
}

static json_t
*find_model(struct model_catalog *catalog, const char *slug)
{
	json_t	*model;
	json_t	*models;
	size_t	index;

	if (slug == NULL || catalog->root == NULL)
		return NULL;
	models = json_object_get(catalog->root, "models");
	json_array_foreach(models, index, model) {
		const char *candidate;

		candidate = json_string_value(json_object_get(model, "slug"));
		if (candidate != NULL && strcmp(candidate, slug) == 0)
			return model;
	}
	return NULL;
}

static int
append_model_name(struct buffer *names, const char *name, size_t *count)
{
	if (*count > 0 && buffer_append_string(names, ", ") == -1)
		return -1;
	if (buffer_append_string(names, name) == -1)
		return -1;
	(*count)++;
	return 0;
}

static int
append_startup_models(struct buffer *names,
    const struct proxy_options *options, const struct model_catalog *catalog,
    size_t *count)
{
	json_t		*models;
	json_t		*model;
	const char	*cursor;
	const char	*comma;
	size_t		index;

	*count = 0;
	if (options->models != NULL) {
		cursor = options->models;
		while (cursor != NULL) {
			comma = strchr(cursor, ',');
			if (comma == NULL)
				comma = cursor + strlen(cursor);
			if (comma > cursor) {
				if ((*count > 0 &&
				    buffer_append_string(names, ", ") == -1) ||
				    buffer_append(names, cursor,
				    (size_t)(comma - cursor)) == -1)
					return -1;
				(*count)++;
			}
			cursor = *comma == '\0' ? NULL : comma + 1;
		}
		return 0;
	}
	models = json_object_get(catalog->root, "models");
	if (!json_is_array(models))
		return -1;
	json_array_foreach(models, index, model) {
		const char *slug;
		const char *visibility;
		json_t *supported;

		slug = json_string_value(json_object_get(model, "slug"));
		visibility = json_string_value(json_object_get(model, "visibility"));
		supported = json_object_get(model, "supported_in_api");
		if (slug != NULL && !json_is_false(supported) &&
		    (visibility == NULL || strcmp(visibility, "list") == 0) &&
		    append_model_name(names, slug, count) == -1)
			return -1;
	}
	return 0;
}

static int
announce_startup(const char *host, const char *port,
    const struct proxy_options *options, const struct model_catalog *catalog)
{
	struct buffer	message;
	struct buffer	names;
	size_t		count;
	char		count_text[32];
	int		length;
	int		result;

	buffer_init(&message);
	buffer_init(&names);
	if (append_startup_models(&names, options, catalog, &count) == -1 ||
	    (count == 0 && buffer_append_string(&names, "none") == -1))
		goto fail;
	length = snprintf(count_text, sizeof(count_text), "%zu", count);
	if (length < 0 || (size_t)length >= sizeof(count_text))
		goto fail;
	if (buffer_append_string(&message, "oaioauthc ready\n  API: http://") == -1 ||
	    buffer_append_string(&message, host) == -1 ||
	    buffer_append_string(&message, ":") == -1 ||
	    buffer_append_string(&message, port) == -1 ||
	    buffer_append_string(&message, "/v1\n  Models (") == -1 ||
	    buffer_append(&message, count_text, (size_t)length) == -1 ||
	    buffer_append_string(&message, "): ") == -1 ||
	    buffer_append(&message, names.data, names.len) == -1 ||
	    buffer_append_string(&message, "\n  Stop: Ctrl-C\n") == -1)
		goto fail;
	result = write_all(STDERR_FILENO, message.data, message.len);
	buffer_free(&names);
	buffer_free(&message);
	return result;

fail:
	buffer_free(&names);
	buffer_free(&message);
	return -1;
}

static int
handle_models(int fd, const struct proxy_options *options,
    const struct auth_session *session, struct model_catalog *catalog)
{
	json_t			*root;
	json_t			*models;
	json_t			*data;
	json_t			*model;
	json_t			*entry;
	size_t			index;
	char			error[256];

	if (options->models != NULL) {
		char *copy;
		char *cursor;
		char *comma;

		data = json_array();
		copy = oaio_strdup(options->models);
		if (copy == NULL)
			return send_error(fd, 500, "out of memory", "server_error");
		cursor = copy;
		while (cursor != NULL) {
			comma = strchr(cursor, ',');
			if (comma != NULL)
				*comma = '\0';
			if (*cursor != '\0')
				json_array_append_new(data, json_pack("{s:s,s:s,s:i,s:s}", "id",
				    cursor, "object", "model", "created", 0, "owned_by",
				    "codex-oauth"));
			cursor = comma == NULL ? NULL : comma + 1;
		}
		free(copy);
		root = json_pack("{s:s,s:o}", "object", "list", "data", data);
		index = (size_t)send_json(fd, 200, root);
		json_decref(root);
		return (int)index;
	}
	if (load_model_catalog(options, session, catalog, error,
	    sizeof(error)) == -1)
		return send_error(fd, 502, error, "upstream_error");
	root = catalog->root;
	models = json_object_get(root, "models");
	data = json_array();
	if (json_is_array(models)) {
		json_array_foreach(models, index, model) {
			const char *slug;
			const char *visibility;
			json_t *supported;

			slug = json_string_value(json_object_get(model, "slug"));
			visibility = json_string_value(json_object_get(model, "visibility"));
			supported = json_object_get(model, "supported_in_api");
			if (slug != NULL && !json_is_false(supported) &&
			    (visibility == NULL || strcmp(visibility, "list") == 0)) {
				entry = json_pack("{s:s,s:s,s:i,s:s}", "id", slug, "object",
				    "model", "created", 0, "owned_by", "codex-oauth");
				json_array_append_new(data, entry);
			}
		}
	}
	if (json_array_size(data) == 0) {
		json_decref(data);
		return send_error(fd, 502, "Codex returned no API-supported "
		    "models for this account.", "upstream_error");
	}
	root = json_pack("{s:s,s:o}", "object", "list", "data", data);
	index = (size_t)send_json(fd, 200, root);
	json_decref(root);
	return (int)index;
}

static int
handle_responses(int fd, const struct proxy_options *options,
    const struct auth_session *session, struct model_catalog *catalog,
    const char *body, int as_chat)
{
	json_t			*request;
	json_t			*upstream_request;
	json_t			*completed;
	json_t			*model;
	char			*request_text;
	char			*url;
	struct http_response	response;
	char			error[256];
	int			want_stream;
	int			use_lite;
	int			result;
	struct stream_client	client;
	struct sse_chat_stream	*chat_stream;

	request = json_load_string_checked(body, error, sizeof(error));
	if (request == NULL)
		return send_error(fd, 400, error, "invalid_request_error");
	debug_json_value(options, "client request", request);
	if (as_chat) {
		upstream_request = json_chat_to_responses(request, error, sizeof(error));
		if (upstream_request == NULL) {
			json_decref(request);
			return send_error(fd, 400, error, "invalid_request_error");
		}
	} else {
		upstream_request = request;
		json_incref(upstream_request);
		if (json_has_replay_state(upstream_request)) {
			json_decref(upstream_request);
			json_decref(request);
			return send_error(fd, 400,
			    "Stateless Codex responses endpoint does not support "
			    "`previous_response_id` or `item_reference`. Replay "
			    "the full conversation history in `input` on each "
			    "request.", "invalid_request_error");
		}
	}
	want_stream = json_is_true(json_object_get(upstream_request, "stream"));
	if (json_normalize_response_request(upstream_request, 1, error,
	    sizeof(error)) == -1) {
		json_decref(upstream_request);
		json_decref(request);
		return send_error(fd, 400, error, "invalid_request_error");
	}
	model = NULL;
	if (load_model_catalog(options, session, catalog, error,
	    sizeof(error)) == 0)
		model = find_model(catalog, json_string_value(json_object_get(
		    upstream_request, "model")));
	use_lite = 0;
	if (model != NULL && json_apply_model_defaults(upstream_request, model,
	    &use_lite, error, sizeof(error)) == -1) {
		json_decref(upstream_request);
		json_decref(request);
		return send_error(fd, 500, error, "server_error");
	}
	debug_json_value(options, "Codex request", upstream_request);
	request_text = json_dump_compact(upstream_request);
	json_decref(upstream_request);
	if (request_text == NULL) {
		json_decref(request);
		return send_error(fd, 500, "out of memory", "server_error");
	}
	url = upstream_url(options, "responses");
	if (url == NULL) {
		free(request_text);
		json_decref(request);
		return send_error(fd, 500, "out of memory", "server_error");
	}
	client.fd = fd;
	client.started = 0;
	chat_stream = NULL;
	if (as_chat && want_stream) {
		chat_stream = sse_chat_stream_new(json_string_value(
		    json_object_get(request, "model")), write_stream, &client);
		if (chat_stream == NULL) {
			free(url);
			free(request_text);
			json_decref(request);
			return send_error(fd, 500, "out of memory", "server_error");
		}
	}
	if (want_stream)
		result = http_post_json_stream(url, request_text,
		    session->access_token, session->account_id, use_lite ?
		    "x-openai-internal-codex-responses-lite: true" : NULL,
		    as_chat ? write_chat_stream : write_stream,
		    as_chat ? (void *)chat_stream : (void *)&client, &response,
		    error, sizeof(error));
	else
		result = http_post_json(url, request_text, session->access_token,
		    session->account_id, use_lite ?
		    "x-openai-internal-codex-responses-lite: true" : NULL,
		    &response, error, sizeof(error));
	free(url);
	free(request_text);
	if (result == -1) {
		sse_chat_stream_free(chat_stream);
		json_decref(request);
		if (client.started)
			return -1;
		return send_error(fd, 502, error, "upstream_error");
	}
	if (response.status < 200 || response.status >= 300) {
		result = send_response(fd, (int)response.status,
		    response.content_type == NULL ? "application/json" :
		    response.content_type,
		    response.body == NULL ? "" : response.body);
		http_response_free(&response);
		sse_chat_stream_free(chat_stream);
		json_decref(request);
		return result;
	}
	if (want_stream) {
		if (as_chat)
			result = sse_chat_stream_finish(chat_stream);
		else
			result = send_stream_headers(&client);
		http_response_free(&response);
		sse_chat_stream_free(chat_stream);
		json_decref(request);
		if (result == -1 && !client.started)
			return send_error(fd, 502, "upstream stream ended before "
			    "completion", "upstream_error");
		return result;
	}
	completed = sse_collect_completed_response(response.body, error,
	    sizeof(error));
	http_response_free(&response);
	if (completed == NULL) {
		json_decref(request);
		return send_error(fd, 502, error, "upstream_error");
	}
	if (as_chat) {
		json_t *chat;

		chat = json_response_to_chat(completed, request, error, sizeof(error));
		json_decref(completed);
		json_decref(request);
		if (chat == NULL)
			return send_error(fd, 502, error, "upstream_error");
		result = send_json(fd, 200, chat);
		json_decref(chat);
		return result;
	}
	json_decref(request);
	result = send_json(fd, 200, completed);
	json_decref(completed);
	return result;
}

static int
content_type_is_multipart(const char *content_type)
{
	const char	*end;
	size_t		 length;

	if (content_type == NULL)
		return 0;
	while (*content_type == ' ' || *content_type == '\t')
		content_type++;
	end = strchr(content_type, ';');
	if (end == NULL)
		end = content_type + strlen(content_type);
	while (end > content_type &&
	    (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	length = (size_t)(end - content_type);
	return length == sizeof("multipart/form-data") - 1 &&
	    strncasecmp(content_type, "multipart/form-data", length) == 0;
}

static int
handle_image(int fd, const struct proxy_options *options,
    const struct auth_session *session, const struct request *request,
    int edit)
{
	struct http_response	response;
	char			error[256];
	char			*prepared;
	char			*url;
	int			 prepared_result;
	int			 result;

	if (edit && !content_type_is_multipart(request->content_type))
		return send_error(fd, 400, "Image editing requires a "
		    "multipart/form-data request body.", "invalid_request_error");
	if (edit)
		prepared_result = image_prepare_edit(request->content_type,
		    request->body, request->body_length, &prepared, error,
		    sizeof(error));
	else
		prepared_result = image_prepare_generation(request->body,
		    request->body_length, &prepared, error, sizeof(error));
	if (prepared_result != IMAGE_RESULT_OK)
		return send_error(fd, prepared_result == IMAGE_RESULT_NOMEM ?
		    500 : 400, error, prepared_result == IMAGE_RESULT_NOMEM ?
		    "server_error" : "invalid_request_error");
	debug_json_text(options, edit ? "Codex image edit request" :
	    "Codex image generation request", prepared);
	url = upstream_url(options, edit ? "images/edits" :
	    "images/generations");
	if (url == NULL) {
		free(prepared);
		return send_error(fd, 500, "out of memory", "server_error");
	}
	result = http_post_json(url, prepared, session->access_token,
	    session->account_id, NULL, &response, error, sizeof(error));
	free(url);
	free(prepared);
	if (result == -1)
		return send_error(fd, 502, error, "upstream_error");
	result = send_response(fd, (int)response.status,
	    response.content_type == NULL ? "application/json" :
	    response.content_type, response.body == NULL ? "" : response.body);
	http_response_free(&response);
	return result;
}

static int
dispatch(int fd, const struct proxy_options *options,
    struct model_catalog *catalog, const struct request *request)
{
	struct auth_session	session;
	char			error[256];
	const char		*auth_file;
	int			result;

	if (strcmp(request->method, "GET") == 0 &&
	    strcmp(request->path, "/health") == 0) {
		json_t *health;

		health = json_pack("{s:b,s:s}", "ok", 1, "replay_state", "stateless");
		result = send_json(fd, 200, health);
		json_decref(health);
		return result;
	}
	auth_file = options->auth_file == NULL ? auth_default_file() :
	    options->auth_file;
	if (auth_file == NULL || auth_load(auth_file, &session, error,
	    sizeof(error)) == -1)
		return send_error(fd, 401, error, "authentication_error");
	if (auth_session_needs_refresh(&session) && auth_refresh(auth_file,
	    options->client_id, options->token_url, &session, error,
	    sizeof(error)) == -1) {
		auth_session_free(&session);
		return send_error(fd, 401, error, "authentication_error");
	}
	if (strcmp(request->method, "GET") == 0 &&
	    strcmp(request->path, "/v1/models") == 0)
		result = handle_models(fd, options, &session, catalog);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/responses") == 0)
		result = handle_responses(fd, options, &session, catalog,
		    request->body, 0);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/chat/completions") == 0)
		result = handle_responses(fd, options, &session, catalog,
		    request->body, 1);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/images/generations") == 0)
		result = handle_image(fd, options, &session, request, 0);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/images/edits") == 0)
		result = handle_image(fd, options, &session, request, 1);
	else
		result = send_error(fd, 404, "Route not found.", "not_found_error");
	auth_session_free(&session);
	return result;
}

int
proxy_serve(const struct proxy_options *options, char *error, size_t length)
{
	struct addrinfo	hints;
	struct addrinfo	*addresses;
	struct addrinfo	*address;
	int		listen_fd;
	int		client_fd;
	int		one;
	pid_t		pid;
	size_t		workers;
	struct sigaction	action;
	struct request	request;
	struct auth_session session;
	struct model_catalog catalog;
	const char	*host;
	const char	*port;
	const char	*auth_file;
	char		*codex_version;
	struct proxy_options	effective_options;

	host = options->host == NULL ? "127.0.0.1" : options->host;
	port = options->port == NULL ? "10531" : options->port;
	memset(&action, 0, sizeof(action));
	action.sa_handler = child_exited;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGCHLD, &action, NULL) == -1) {
		set_error(error, length, "could not configure child handling");
		return -1;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host, port, &hints, &addresses) != 0) {
		set_error(error, length, "could not resolve listen address");
		return -1;
	}
	listen_fd = -1;
	for (address = addresses; address != NULL; address = address->ai_next) {
		listen_fd = socket(address->ai_family, address->ai_socktype,
		    address->ai_protocol);
		if (listen_fd == -1)
			continue;
		one = 1;
		(void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (bind(listen_fd, address->ai_addr, address->ai_addrlen) == 0)
			break;
		close(listen_fd);
		listen_fd = -1;
	}
	freeaddrinfo(addresses);
	if (listen_fd == -1 || listen(listen_fd, 16) == -1) {
		if (listen_fd != -1)
			close(listen_fd);
		set_error(error, length, "could not listen on %s:%s: %s", host, port,
		    strerror(errno));
		return -1;
	}
	codex_version = resolve_codex_version(options, error, length);
	if (codex_version == NULL) {
		close(listen_fd);
		return -1;
	}
	effective_options = *options;
	effective_options.codex_version = codex_version;
	memset(&catalog, 0, sizeof(catalog));
	if (options->models == NULL) {
		auth_file = options->auth_file == NULL ? auth_default_file() :
		    options->auth_file;
		if (auth_file == NULL || auth_load(auth_file, &session, error,
		    length) == -1) {
			close(listen_fd);
			free(codex_version);
			return -1;
		}
		if (auth_session_needs_refresh(&session) && auth_refresh(auth_file,
		    options->client_id, options->token_url, &session, error,
		    length) == -1) {
			auth_session_free(&session);
			close(listen_fd);
			free(codex_version);
			return -1;
		}
		if (load_model_catalog(&effective_options, &session, &catalog, error,
		    length) == -1) {
			auth_session_free(&session);
			close(listen_fd);
			free(codex_version);
			return -1;
		}
		auth_session_free(&session);
	}
	if (announce_startup(host, port, &effective_options, &catalog) == -1) {
		model_catalog_free(&catalog);
		close(listen_fd);
		free(codex_version);
		set_error(error, length, "could not write startup message");
		return -1;
	}
	workers = 0;
	for (;;) {
		while (waitpid(-1, NULL, WNOHANG) > 0) {
			if (workers > 0)
				workers--;
		}
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		set_client_timeout(client_fd);
		if (workers >= MAX_WORKERS) {
			(void)send_error(client_fd, 503,
			    "Too many concurrent requests.", "server_error");
			close(client_fd);
			continue;
		}
		pid = fork();
		if (pid == -1) {
			(void)send_error(client_fd, 503,
			    "Could not start request worker.", "server_error");
			close(client_fd);
			continue;
		}
		if (pid == 0) {
			close(listen_fd);
			if (read_request(client_fd, &request) == -1)
				(void)send_error(client_fd, 400,
				    "Malformed HTTP request.",
				    "invalid_request_error");
			else {
				(void)dispatch(client_fd, &effective_options,
				    &catalog,
				    &request);
				request_free(&request);
			}
			model_catalog_free(&catalog);
			close(client_fd);
			_exit(0);
		}
		workers++;
		close(client_fd);
	}
	close(listen_fd);
	model_catalog_free(&catalog);
	free(codex_version);
	set_error(error, length, "server accept failed: %s", strerror(errno));
	return -1;
}
