#include "proxy.h"
#include "auth.h"
#include "http.h"
#include "json.h"
#include "sse.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_BASE_URL "https://chatgpt.com/backend-api/codex"
#define DEFAULT_CODEX_VERSION "0.145.0"
#define MAX_REQUEST_SIZE (8 * 1024 * 1024)
#define CLIENT_TIMEOUT 30

struct request {
	char	*method;
	char	*path;
	char	*body;
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

static void
request_free(struct request *request)
{
	free(request->method);
	free(request->path);
	free(request->body);
	memset(request, 0, sizeof(*request));
}

static int
read_more(int fd, struct buffer *buffer)
{
	char	chunk[4096];
	ssize_t	count;

	do {
		count = read(fd, chunk, sizeof(chunk));
	} while (count == -1 && errno == EINTR);
	if (count <= 0 || buffer->len > MAX_REQUEST_SIZE - (size_t)count)
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
    struct request *request)
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
			if (read_more(fd, raw) == -1)
				goto fail;
		}
		line_length = (size_t)(line_end - (raw->data + cursor));
		if (line_length == 0 || line_length >= sizeof(number))
			goto fail;
		memcpy(number, raw->data + cursor, line_length);
		number[line_length] = '\0';
		errno = 0;
		chunk_length = strtoull(number, &end, 16);
		if (errno != 0 || end == number || *end != '\0' ||
		    chunk_length > MAX_REQUEST_SIZE - body.len)
			goto fail;
		cursor = (size_t)(line_end - raw->data) + 2;
		while (raw->len - cursor < (size_t)chunk_length + 2) {
			if (read_more(fd, raw) == -1)
				goto fail;
		}
		if (raw->data[cursor + (size_t)chunk_length] != '\r' ||
		    raw->data[cursor + (size_t)chunk_length + 1] != '\n')
			goto fail;
		if (buffer_append(&body, raw->data + cursor,
		    (size_t)chunk_length) == -1)
			goto fail;
		cursor += (size_t)chunk_length + 2;
		if (chunk_length == 0)
			break;
	}
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
	int		has_content_length;
	int		expect_continue;
	int		chunked;
	int		last_header;

	memset(request, 0, sizeof(*request));
	buffer_init(&buffer);
	while ((header_end = buffer.data == NULL ? NULL : strstr(buffer.data,
	    "\r\n\r\n")) == NULL) {
		if (read_more(fd, &buffer) == -1) {
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
	if (length > MAX_REQUEST_SIZE) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	if (expect_continue &&
	    write_all(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25) == -1) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	if (chunked) {
		if (read_chunked_body(fd, &buffer, body_offset, request) == -1) {
			request_free(request);
			buffer_free(&buffer);
			return -1;
		}
		buffer_free(&buffer);
		return 0;
	}
	while (buffer.len - body_offset < length) {
		if (read_more(fd, &buffer) == -1) {
			request_free(request);
			buffer_free(&buffer);
			return -1;
		}
	}
	request->body = malloc(length + 1);
	if (request->body == NULL) {
		request_free(request);
		buffer_free(&buffer);
		return -1;
	}
	memcpy(request->body, buffer.data + body_offset, length);
	request->body[length] = '\0';
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
	    (base[strlen(base) - 1] == '/' ? 0 : buffer_append_string(&buffer, "/")) == -1 ||
	    buffer_append_string(&buffer, suffix) == -1) {
		buffer_free(&buffer);
		return NULL;
	}
	return buffer_steal(&buffer);
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

	if (catalog->root != NULL && catalog->account_id != NULL &&
	    strcmp(catalog->account_id, session->account_id) == 0 &&
	    catalog->expires > time(NULL))
		return 0;
	url = upstream_url(options, "models?client_version=");
	version = http_form_encode(options->codex_version == NULL ?
	    DEFAULT_CODEX_VERSION : options->codex_version);
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
	if (!json_is_object(root) ||
	    !json_is_array(json_object_get(root, "models"))) {
		json_decref(root);
		set_error(error, length, "Codex returned a malformed models response");
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

	request = json_load_string_checked(body, error, sizeof(error));
	if (request == NULL)
		return send_error(fd, 400, error, "invalid_request_error");
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
			return send_error(fd, 400, "Stateless Codex responses endpoint does not support `previous_response_id` or `item_reference`. Replay the full conversation history in `input` on each request.", "invalid_request_error");
		}
	}
	want_stream = json_is_true(json_object_get(upstream_request, "stream"));
	if (json_normalize_response_request(upstream_request, 1, error, sizeof(error)) == -1) {
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
	if (!as_chat && want_stream)
		result = http_post_json_stream(url, request_text,
		    session->access_token, session->account_id, use_lite ?
		    "x-openai-internal-codex-responses-lite: true" : NULL,
		    write_stream, &client, &response, error, sizeof(error));
	else
		result = http_post_json(url, request_text, session->access_token,
		    session->account_id, use_lite ?
		    "x-openai-internal-codex-responses-lite: true" : NULL,
		    &response, error, sizeof(error));
	free(url);
	free(request_text);
	if (result == -1) {
		json_decref(request);
		if (client.started)
			return -1;
		return send_error(fd, 502, error, "upstream_error");
	}
	if (response.status < 200 || response.status >= 300) {
		result = send_response(fd, (int)response.status,
		    response.content_type == NULL ? "application/json" : response.content_type,
		    response.body == NULL ? "" : response.body);
		http_response_free(&response);
		json_decref(request);
		return result;
	}
	if (!as_chat && want_stream) {
		result = send_stream_headers(&client);
		http_response_free(&response);
		json_decref(request);
		return result;
	}
	completed = sse_collect_completed_response(response.body, error, sizeof(error));
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
		if (want_stream) {
			json_t *message;
			json_t *chunk;
			json_t *final_chunk;
			struct buffer stream;
			char *text;

			message = json_object_get(json_array_get(json_object_get(chat,
			    "choices"), 0), "message");
			chunk = json_pack("{s:s,s:s,s:i,s:s,s:[{s:i,s:{s:s,s:o},s:n}]}",
			    "id", "chatcmpl_local", "object", "chat.completion.chunk",
			    "created", 0, "model", json_string_value(json_object_get(chat,
			    "model")) == NULL ? "" : json_string_value(json_object_get(chat,
			    "model")), "choices", "index", 0, "delta", "role", "assistant",
			    "content", json_deep_copy(json_object_get(message, "content")),
			    "finish_reason");
			final_chunk = json_pack("{s:s,s:s,s:i,s:s,s:[{s:i,s:{},s:s}]}",
			    "id", "chatcmpl_local", "object", "chat.completion.chunk",
			    "created", 0, "model", json_string_value(json_object_get(chat,
			    "model")) == NULL ? "" : json_string_value(json_object_get(chat,
			    "model")), "choices", "index", 0, "delta", "finish_reason", "stop");
			buffer_init(&stream);
			text = json_dump_compact(chunk);
			(void)buffer_append_string(&stream, "data: ");
			(void)buffer_append_string(&stream, text);
			(void)buffer_append_string(&stream, "\n\n");
			free(text);
			text = json_dump_compact(final_chunk);
			(void)buffer_append_string(&stream, "data: ");
			(void)buffer_append_string(&stream, text);
			(void)buffer_append_string(&stream, "\n\ndata: [DONE]\n\n");
			free(text);
			json_decref(chunk);
			json_decref(final_chunk);
			result = send_response(fd, 200, "text/event-stream; charset=utf-8",
			    stream.data);
			buffer_free(&stream);
		} else
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
dispatch(int fd, const struct proxy_options *options,
    struct model_catalog *catalog, const struct request *request)
{
	struct auth_session	session;
	char			error[256];
	const char		*auth_file;
	int			result;

	if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/health") == 0) {
		json_t *health;

		health = json_pack("{s:b,s:s}", "ok", 1, "replay_state", "stateless");
		result = send_json(fd, 200, health);
		json_decref(health);
		return result;
	}
	auth_file = options->auth_file == NULL ? auth_default_file() : options->auth_file;
	if (auth_file == NULL || auth_load(auth_file, &session, error, sizeof(error)) == -1)
		return send_error(fd, 401, error, "authentication_error");
	if (auth_session_needs_refresh(&session) && auth_refresh(auth_file,
	    options->client_id, options->token_url, &session, error,
	    sizeof(error)) == -1) {
		auth_session_free(&session);
		return send_error(fd, 401, error, "authentication_error");
	}
	if (strcmp(request->method, "GET") == 0 && strcmp(request->path, "/v1/models") == 0)
		result = handle_models(fd, options, &session, catalog);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/responses") == 0)
		result = handle_responses(fd, options, &session, catalog,
		    request->body, 0);
	else if (strcmp(request->method, "POST") == 0 && strcmp(request->path,
	    "/v1/chat/completions") == 0)
		result = handle_responses(fd, options, &session, catalog,
		    request->body, 1);
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
	struct request	request;
	struct model_catalog	catalog;
	const char	*host;
	const char	*port;

	host = options->host == NULL ? "127.0.0.1" : options->host;
	port = options->port == NULL ? "10531" : options->port;
	memset(&catalog, 0, sizeof(catalog));
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
	(void)fprintf(stderr, "OpenAI-compatible endpoint ready at http://%s:%s/v1\n",
	    host, port);
	for (;;) {
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		set_client_timeout(client_fd);
		if (read_request(client_fd, &request) == -1)
			(void)send_error(client_fd, 400, "Malformed HTTP request.",
			    "invalid_request_error");
		else {
			(void)dispatch(client_fd, options, &catalog, &request);
			request_free(&request);
		}
		close(client_fd);
	}
	model_catalog_free(&catalog);
	close(listen_fd);
	set_error(error, length, "server accept failed: %s", strerror(errno));
	return -1;
}
