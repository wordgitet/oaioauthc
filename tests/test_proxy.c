/*
 * End-to-end local proxy test with a forked deterministic Codex mock.
 *
 * It exercises the public HTTP routes, streaming conversion, image request
 * translation, startup behavior, and diagnostic redaction without real OAuth
 * credentials or network access.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "util.h"

/*
** Assert a process-level condition and centralize descriptor/process cleanup.
**
** Unlike CHECK, proxy test failures may leave child processes and temporary
** files behind, so every failure jumps to the cleanup block in main.
*/
#define REQUIRE(condition)                                                     \
	do {                                                                   \
		if (!(condition)) {                                            \
			(void)fprintf(stderr, "%s:%d: check failed: %s\n",     \
			    __FILE__, __LINE__, #condition);                   \
			goto cleanup;                                          \
		}                                                              \
	} while (0)

/* Reserve an unused loopback port, then release it for a child to bind. */
static int
reserve_port(char *port, size_t length)
{
	struct sockaddr_in address;
	socklen_t	   address_length;
	int		   fd;
	int		   result;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	address_length = sizeof(address);
	result = bind(fd, (struct sockaddr *)&address, sizeof(address));
	if (result == 0)
		result = getsockname(fd, (struct sockaddr *)&address,
		    &address_length);
	if (result == 0 &&
	    snprintf(port, length, "%u",
		(unsigned int)ntohs(address.sin_port)) >= (int)length)
		result = -1;
	close(fd);
	return result;
}

/* Bind the deterministic mock to a caller-reserved loopback port. */
static int
listen_port(const char *port)
{
	struct sockaddr_in address;
	int		   fd;
	int		   one;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	one = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons((unsigned short)atoi(port));
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    listen(fd, 8) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Extract Content-Length from the mock's small HTTP request parser. */
static size_t
content_length(const char *request)
{
	const char *cursor;
	const char *end;

	cursor = request;
	while ((end = strstr(cursor, "\r\n")) != NULL) {
		if (strncasecmp(cursor, "Content-Length:", 15) == 0)
			return (size_t)strtoul(cursor + 15, NULL, 10);
		cursor = end + 2;
	}
	return 0;
}

/* Read one complete mock request, including its declared body, into request. */
static int
read_mock_request(int fd, char *request, size_t length)
{
	char   *headers;
	ssize_t count;
	size_t	used;
	size_t	body_length;

	used = 0;
	headers = NULL;
	while (used + 1 < length) {
		count = read(fd, request + used, length - used - 1);
		if (count == -1)
			return -1;
		if (count == 0)
			break;
		used += (size_t)count;
		request[used] = '\0';
		headers = strstr(request, "\r\n\r\n");
		if (headers != NULL) {
			body_length = content_length(request);
			if (used >=
			    (size_t)(headers + 4 - request) + body_length)
				break;
		}
	}
	request[used] = '\0';
	return headers == NULL ? -1 : 0;
}

/* Write the exact fixed-length HTTP response used by the local mock. */
static int
send_mock_response(int fd, const char *content_type, const char *body)
{
	char header[256];
	int  length;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
	    content_type, strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header))
		return -1;
	if (write_all(fd, header, (size_t)length) == -1)
		return -1;
	return write_all(fd, body, strlen(body));
}

/* Write an upstream error response while retaining the mock's fixed framing. */
static int
send_mock_error(int fd, int status, const char *body)
{
	char header[256];
	int  length;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 %d Test\r\nContent-Type: application/json\r\n"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n", status,
	    strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header))
		return (-1);
	if (write_all(fd, header, (size_t)length) == -1)
		return (-1);
	return (write_all(fd, body, strlen(body)));
}

/* Emit deliberately awkward SSE fragments to exercise transport boundaries. */
static int
send_mock_stream(int fd, const char *body)
{
	static const size_t fragments[] = { 1, 7, 3, 19 };
	struct timespec     delay;
	char		 header[256];
	int		 length;
	size_t		 index;
	size_t		 offset;
	size_t		 fragment;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n", strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header) ||
	    write_all(fd, header, (size_t)length) == -1)
		return (-1);
	delay.tv_sec = 0;
	delay.tv_nsec = 1000000;
	offset = 0;
	index = 0;
	while (offset < strlen(body)) {
		fragment = fragments[index++ %
		    (sizeof(fragments) / sizeof(fragments[0]))];
		if (fragment > strlen(body) - offset)
			fragment = strlen(body) - offset;
		if (write_all(fd, body + offset, fragment) == -1)
			return (-1);
		offset += fragment;
		(void)nanosleep(&delay, NULL);
	}
	return (0);
}

/*
** Run the deterministic Codex stand-in until the parent terminates it.
**
** The readiness byte is written only after listen succeeds, preventing startup
** model discovery from racing the mock bind.  Route checks also assert that
** the proxy normalized images and removed intentionally unsupported fields.
*/
static void
run_mock_upstream(const char *port, int ready_fd)
{
	static const char models[] =
	    "{\"models\":[{\"slug\":\"gpt-test\",\"visibility\":\"list\","
	    "\"supported_in_api\":true}]}";
	static const char events[] =
	    "data: {\"type\":\"response.created\",\"response\":{\"id\":"
	    "\"resp_test\"}}\n\n"
	    "data: {\"type\":\"response.output_text.delta\","
	    "\"delta\":\"hello\"}\n\n"
	    "data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":"
	    "\"msg_test\",\"type\":\"message\",\"content\":[{\"type\":"
	    "\"output_text\",\"text\":\"hello\"}]}}\n\n"
	    "data: {\"type\":\"response.completed\",\"response\":{\"id\":"
	    "\"resp_test\",\"status\":\"completed\",\"output\":[],\"usage\":{"
	    "\"input_tokens\":2,\"output_tokens\":1,\"total_tokens\":3,"
	    "\"input_tokens_details\":{\"cached_tokens\":1},"
	    "\"output_tokens_details\":{\"reasoning_tokens\":1}}}}\n\n";
	static const char image[] =
	    "{\"created\":1,\"data\":[{\"b64_json\":\"AQID\"}],"
	    "\"usage\":{\"total_tokens\":5}}";
	static const char truncated_events[] =
	    "data: {\"type\":\"response.created\",\"response\":{\"id\":"
	    "\"resp_truncated\"}}\n\n"
	    "data: {\"type\":\"response.output_text.delta\","
	    "\"delta\":\"incomplete\"}\n\n";
	static const char upstream_error[] =
	    "{\"error\":{\"message\":\"mock upstream rejected request\","
	    "\"type\":\"rate_limit_error\"}}";
	char request[32768];
	char ready;
	int  client_fd;
	int  listen_fd;

	listen_fd = listen_port(port);
	if (listen_fd == -1)
		_exit(1);
	ready = 1;
	if (write_all(ready_fd, &ready, sizeof(ready)) == -1)
		_exit(1);
	close(ready_fd);
	for (;;) {
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1)
			continue;
		if (read_mock_request(client_fd, request, sizeof(request)) ==
		    0) {
			if (strncmp(request, "GET /models?", 12) == 0)
				(void)send_mock_response(client_fd,
				    "application/json", models);
			else if (strncmp(request, "POST /responses ", 16) == 0) {
				if (strstr(request, "please fail upstream") != NULL)
					(void)send_mock_error(client_fd, 429, upstream_error);
				else if (strstr(request, "please truncate upstream") !=
				    NULL)
					(void)send_mock_stream(client_fd, truncated_events);
				else if (strstr(request, "continue") != NULL &&
				    (strstr(request, "\"type\":\"output_text\"") ==
				    NULL || strstr(request, "\"text\":\"hello\"") ==
				    NULL))
					(void)send_mock_error(client_fd, 500,
					    "{\"error\":\"assistant history was not normalized\"}");
				else
					(void)send_mock_stream(client_fd, events);
			}
			else if (strncmp(request, "POST /images/generations ",
				     25) == 0 &&
			    strstr(request, "\"model\":\"image-model\"") !=
				NULL &&
			    strstr(request, "\"prompt\":\"draw a square\"") !=
				NULL &&
			    strstr(request, "\"ignored\"") == NULL)
				(void)send_mock_response(client_fd,
				    "application/json", image);
			else if (strncmp(request, "POST /images/edits ", 19) ==
				0 &&
			    strstr(request, "\"model\":\"image-model\"") !=
				NULL &&
			    strstr(request, "\"prompt\":\"add a red hat\"") !=
				NULL &&
			    strstr(request,
				"\"image_url\":\"data:image/png;base64,YWJj\"") !=
				NULL)
				(void)send_mock_response(client_fd,
				    "application/json", image);
			else
				(void)send_mock_response(client_fd,
				    "application/json", "{}");
		}
		close(client_fd);
	}
}

/* Connect one test client to the loopback proxy. */
static int
open_port(const char *port)
{
	struct sockaddr_in address;
	int		   fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons((unsigned short)atoi(port));
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Send a raw HTTP request and collect the connection-close response. */
static int
request_port(const char *port, const char *request, char *response,
    size_t response_length)
{
	int	fd;
	ssize_t count;
	size_t	length;

	fd = open_port(port);
	if (fd == -1 || write_all(fd, request, strlen(request)) == -1) {
		if (fd != -1)
			close(fd);
		return -1;
	}
	length = 0;
	while (length + 1 < response_length &&
	    (count = read(fd, response + length,
		 response_length - length - 1)) > 0)
		length += (size_t)count;
	response[length] = '\0';
	close(fd);
	return 0;
}

/* Build and send a minimal JSON POST request to one public proxy path. */
static int
request_json(const char *port, const char *path, const char *body,
    char *response, size_t response_length)
{
	char request[2048];
	int  length;

	length = snprintf(request, sizeof(request),
	    "POST %s HTTP/1.1\r\nHost: localhost\r\n"
	    "Content-Length: %zu\r\n\r\n%s",
	    path, strlen(body), body);
	if (length < 0 || (size_t)length >= sizeof(request))
		return -1;
	return request_port(port, request, response, response_length);
}

/* Build and send a multipart POST while preserving supplied body bytes. */
static int
request_multipart(const char *port, const char *path, const char *boundary,
    const char *body, char *response, size_t response_length)
{
	char request[4096];
	int  length;

	length = snprintf(request, sizeof(request),
	    "POST %s HTTP/1.1\r\nHost: localhost\r\n"
	    "Content-Type: multipart/form-data; boundary=%s\r\n"
	    "Content-Length: %zu\r\n\r\n%s",
	    path, boundary, strlen(body), body);
	if (length < 0 || (size_t)length >= sizeof(request))
		return -1;
	return request_port(port, request, response, response_length);
}

/* Poll unauthenticated /health until the forked proxy listener accepts work. */
static int
wait_for_proxy(const char *port, char *response, size_t length)
{
	struct timespec delay;
	int		attempt;

	delay.tv_sec = 0;
	delay.tv_nsec = 10000000;
	for (attempt = 0; attempt < 200; attempt++) {
		if (request_port(port,
			"GET /health HTTP/1.1\r\n"
			"Host: localhost\r\n\r\n",
			response, length) == 0)
			return 0;
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

/*
** Exercise public routes against the local mock and inspect server diagnostics.
**
** The scenario also verifies the listener survives missing credentials and a
** closed stderr, which are startup availability properties rather than route
** response behavior.
*/
int
main(void)
{
	char	      path[] = "/tmp/oaioauthc-proxy-XXXXXX";
	char	      debug_path[] = "/tmp/oaioauthc-debug-XXXXXX";
	char	      base_url[128];
	char	      mock_port[16];
	char	      port[16];
	char	      response[16384];
	const char   *edit_body;
	struct buffer debug_output;
	pid_t	      mock_pid;
	pid_t	      pid;
	int	      fd;
	int	      debug_fd;
	int	      mock_ready[2];
	int	      result;
	int	      slow_fd;
	int	      status;
	char	      ready;

	pid = -1;
	mock_pid = -1;
	slow_fd = -1;
	debug_fd = -1;
	mock_ready[0] = -1;
	mock_ready[1] = -1;
	result = 1;
	buffer_init(&debug_output);
	fd = mkstemp(path);
	REQUIRE(fd != -1);
	REQUIRE(close(fd) == 0);
	REQUIRE(write_private_file(path,
		    "{\"tokens\":{\"access_token\":\"access\","
		    "\"account_id\":\"acct_1\"}}") == 0);
	debug_fd = mkstemp(debug_path);
	REQUIRE(debug_fd != -1);
	REQUIRE(close(debug_fd) == 0);
	debug_fd = -1;
	REQUIRE(reserve_port(port, sizeof(port)) == 0);
	REQUIRE(reserve_port(mock_port, sizeof(mock_port)) == 0);
	REQUIRE(snprintf(base_url, sizeof(base_url), "http://127.0.0.1:%s",
		    mock_port) < (int)sizeof(base_url));
	REQUIRE(pipe(mock_ready) == 0);
	mock_pid = fork();
	REQUIRE(mock_pid != -1);
	if (mock_pid == 0) {
		close(mock_ready[0]);
		run_mock_upstream(mock_port, mock_ready[1]);
	}
	close(mock_ready[1]);
	mock_ready[1] = -1;
	REQUIRE(read(mock_ready[0], &ready, sizeof(ready)) == sizeof(ready));
	close(mock_ready[0]);
	mock_ready[0] = -1;
	pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		debug_fd = open(debug_path, O_WRONLY | O_APPEND);
		if (debug_fd == -1 || dup2(debug_fd, STDERR_FILENO) == -1)
			_exit(126);
		close(debug_fd);
		execl(TEST_PROGRAM_PATH, "oaioauthc", "serve", "-p", port,
		    "--oauth-file", path, "--base-url", base_url,
		    "--codex-version", "9.9.9", "--debug-json", (char *)NULL);
		_exit(127);
	}
	REQUIRE(wait_for_proxy(port, response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "200 OK") != NULL);
	REQUIRE(strstr(response, "\"replay_state\":\"stateless\"") != NULL);
	slow_fd = open_port(port);
	REQUIRE(slow_fd != -1);
	REQUIRE(write_all(slow_fd, "GET /", 5) == 0);
	REQUIRE(wait_for_proxy(port, response, sizeof(response)) == 0);
	REQUIRE(close(slow_fd) == 0);
	slow_fd = -1;
	REQUIRE(request_port(port,
		    "GET /v1/models HTTP/1.1\r\n"
		    "Host: localhost\r\n\r\n",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"id\":\"gpt-test\"") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
		    "{\"model\":\"gpt-test\",\"input\":\"hi\","
		    "\"access_token\":\"debug-secret\","
		    "\"id_token\":\"identity-secret\",\"metadata\":{"
		    "\"asset\":\"DATA:image/svg+xml,%3Csvg/%3E\"}}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"status\":\"completed\"") != NULL);
	REQUIRE(strstr(response, "\"text\":\"hello\"") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
		    "{\"model\":\"gpt-test\",\"input\":\"hi\",\"stream\":true}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "response.output_text.delta") != NULL);
	REQUIRE(strstr(response, "\"output\":[{\"id\":\"msg_test\"") != NULL);
	REQUIRE(request_json(port, "/v1/chat/completions",
		    "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\","
		    "\"content\":\"hi\"}]}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"content\":\"hello\"") != NULL);
	REQUIRE(strstr(response, "\"prompt_tokens\":2") != NULL);
	REQUIRE(strstr(response, "\"cached_tokens\":1") != NULL);
	REQUIRE(request_json(port, "/v1/chat/completions",
		    "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\","
		    "\"content\":\"hi\"},{\"role\":\"assistant\",\"content\":"
		    "\"hello\"},{\"role\":\"user\",\"content\":\"continue\"}],"
		    "\"stream\":true}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"content\":\"hello\"") != NULL);
	REQUIRE(strstr(response, "\"prompt_tokens\":2") != NULL);
	REQUIRE(strstr(response, "\"reasoning_tokens\":1") != NULL);
	REQUIRE(strstr(response, "data: [DONE]") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
	    "{\"model\":\"gpt-test\",\"input\":\"please fail upstream\"}",
	    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "429 Error") != NULL);
	REQUIRE(strstr(response, "mock upstream rejected request") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
	    "{\"model\":\"gpt-test\",\"input\":\"please truncate upstream\"}",
	    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "502 Error") != NULL);
	REQUIRE(request_json(port, "/v1/images/generations",
		    "{\"model\":\"image-model\",\"prompt\":\"draw a square\","
		    "\"response_format\":\"b64_json\",\"ignored\":true}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"b64_json\":\"AQID\"") != NULL);
	edit_body = "--edit\r\n"
		    "Content-Disposition: form-data; name=\"model\"\r\n\r\n"
		    "image-model\r\n"
		    "--edit\r\n"
		    "Content-Disposition: form-data; name=\"prompt\"\r\n\r\n"
		    "add a red hat\r\n"
		    "--edit\r\n"
		    "Content-Disposition: form-data; name=\"image\"; "
		    "filename=\"input.png\"\r\n"
		    "Content-Type: image/png\r\n\r\n"
		    "abc\r\n"
		    "--edit--\r\n";
	REQUIRE(request_multipart(port, "/v1/images/edits", "edit", edit_body,
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"b64_json\":\"AQID\"") != NULL);
	REQUIRE(request_json(port, "/v1/images/generations",
		    "{\"prompt\":\"draw a square\"}", response,
		    sizeof(response)) == 0);
	REQUIRE(strstr(response, "400 Error") != NULL);
	REQUIRE(strstr(response, "`model`") != NULL);
	REQUIRE(request_json(port, "/v1/images/edits", "{}", response,
		    sizeof(response)) == 0);
	REQUIRE(strstr(response, "multipart/form-data") != NULL);
	REQUIRE(request_port(port,
		    "POST /missing HTTP/1.1\r\n"
		    "Host: localhost\r\ncontent-length: 2\r\n\r\n{}",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	REQUIRE(request_port(port,
		    "POST /missing HTTP/1.1\r\n"
		    "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
		    "2;test=yes\r\n{}\r\n0\r\nX-Test: yes\r\n\r\n",
		    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	REQUIRE(read_file(debug_path, &debug_output) == 0);
	REQUIRE(strstr(debug_output.data, "oaioauthc ready\n") != NULL);
	REQUIRE(strstr(debug_output.data, "Models (1): gpt-test") != NULL);
	REQUIRE(strstr(debug_output.data, "client request") != NULL);
	REQUIRE(strstr(debug_output.data, "Codex request") != NULL);
	REQUIRE(
	    strstr(debug_output.data, "client request: {\"model\"") != NULL);
	REQUIRE(strstr(debug_output.data, "\"type\":\"output_text\"") != NULL);
	REQUIRE(strstr(debug_output.data, "[redacted data URL:") != NULL);
	REQUIRE(
	    strstr(debug_output.data, "data:image/png;base64,YWJj") == NULL);
	REQUIRE(strstr(debug_output.data, "\"access_token\":\"[redacted]\"") !=
	    NULL);
	REQUIRE(
	    strstr(debug_output.data, "\"id_token\":\"[redacted]\"") != NULL);
	REQUIRE(strstr(debug_output.data, "debug-secret") == NULL);
	REQUIRE(strstr(debug_output.data, "identity-secret") == NULL);
	REQUIRE(strstr(debug_output.data, "DATA:image/svg+xml") == NULL);
	REQUIRE(strstr(debug_output.data, "acct_1") == NULL);
	REQUIRE(kill(pid, SIGTERM) == 0);
	REQUIRE(waitpid(pid, &status, 0) == pid);
	pid = -1;
	buffer_free(&debug_output);
	buffer_init(&debug_output);
	debug_fd = open(debug_path, O_WRONLY | O_TRUNC);
	REQUIRE(debug_fd != -1);
	REQUIRE(close(debug_fd) == 0);
	debug_fd = -1;
	REQUIRE(reserve_port(port, sizeof(port)) == 0);
	pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		debug_fd = open(debug_path, O_WRONLY | O_APPEND);
		if (debug_fd == -1 || dup2(debug_fd, STDERR_FILENO) == -1)
			_exit(126);
		close(debug_fd);
		execl(TEST_PROGRAM_PATH, "oaioauthc", "serve", "--port", port,
		    "--oauth-file", path, "--base-url", base_url,
		    "--codex-version", "9.9.9", "--debug-json=pretty",
		    (char *)NULL);
		_exit(127);
	}
	REQUIRE(wait_for_proxy(port, response, sizeof(response)) == 0);
	REQUIRE(request_json(port, "/v1/responses",
		    "{\"model\":\"gpt-test\",\"input\":\"pretty\"}", response,
		    sizeof(response)) == 0);
	REQUIRE(read_file(debug_path, &debug_output) == 0);
	REQUIRE(strstr(debug_output.data,
		    "client request: {\n  \"model\": \"gpt-test\"") != NULL);
	REQUIRE(kill(pid, SIGTERM) == 0);
	REQUIRE(waitpid(pid, &status, 0) == pid);
	pid = -1;
	REQUIRE(unlink(path) == 0);
	REQUIRE(reserve_port(port, sizeof(port)) == 0);
	pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		close(STDERR_FILENO);
		execl(TEST_PROGRAM_PATH, "oaioauthc", "serve", "--port", port,
		    "--oauth-file", path, "--base-url", base_url,
		    "--codex-version", "9.9.9", (char *)NULL);
		_exit(127);
	}
	REQUIRE(wait_for_proxy(port, response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "200 OK") != NULL);
	result = 0;

cleanup:
	buffer_free(&debug_output);
	if (debug_fd != -1)
		close(debug_fd);
	if (mock_ready[0] != -1)
		close(mock_ready[0]);
	if (mock_ready[1] != -1)
		close(mock_ready[1]);
	if (slow_fd != -1)
		close(slow_fd);
	if (pid > 0) {
		(void)kill(pid, SIGTERM);
		(void)waitpid(pid, &status, 0);
	}
	if (mock_pid > 0) {
		(void)kill(mock_pid, SIGTERM);
		(void)waitpid(mock_pid, &status, 0);
	}
	(void)unlink(path);
	(void)unlink(debug_path);
	return result;
}
