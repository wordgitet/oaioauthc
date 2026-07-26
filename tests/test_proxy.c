#include "util.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do {						\
	if (!(condition)) {						\
		(void)fprintf(stderr, "%s:%d: check failed: %s\n",	\
		    __FILE__, __LINE__, #condition);			\
		goto cleanup;						\
	}								\
} while (0)

static int
reserve_port(char *port, size_t length)
{
	struct sockaddr_in	address;
	socklen_t		address_length;
	int			fd;
	int			result;

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
	if (result == 0 && snprintf(port, length, "%u",
	    (unsigned int)ntohs(address.sin_port)) >= (int)length)
		result = -1;
	close(fd);
	return result;
}

static int
listen_port(const char *port)
{
	struct sockaddr_in	address;
	int			fd;
	int			one;

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

static size_t
content_length(const char *request)
{
	const char	*cursor;
	const char	*end;

	cursor = request;
	while ((end = strstr(cursor, "\r\n")) != NULL) {
		if (strncasecmp(cursor, "Content-Length:", 15) == 0)
			return (size_t)strtoul(cursor + 15, NULL, 10);
		cursor = end + 2;
	}
	return 0;
}

static int
read_mock_request(int fd, char *request, size_t length)
{
	char	*headers;
	ssize_t	count;
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
			if (used >= (size_t)(headers + 4 - request) + body_length)
				break;
		}
	}
	request[used] = '\0';
	return headers == NULL ? -1 : 0;
}

static int
send_mock_response(int fd, const char *content_type, const char *body)
{
	char	header[256];
	int	length;

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

static void
run_mock_upstream(const char *port)
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
	char	request[32768];
	int	client_fd;
	int	listen_fd;

	listen_fd = listen_port(port);
	if (listen_fd == -1)
		_exit(1);
	for (;;) {
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1)
			continue;
		if (read_mock_request(client_fd, request, sizeof(request)) == 0) {
			if (strncmp(request, "GET /models?", 12) == 0)
				(void)send_mock_response(client_fd,
				    "application/json", models);
			else if (strncmp(request, "POST /responses ", 16) == 0)
				(void)send_mock_response(client_fd,
				    "text/event-stream", events);
			else
				(void)send_mock_response(client_fd,
				    "application/json", "{}");
		}
		close(client_fd);
	}
}

static int
open_port(const char *port)
{
	struct sockaddr_in	address;
	int			fd;

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

static int
request_port(const char *port, const char *request, char *response,
    size_t response_length)
{
	int	fd;
	ssize_t	count;
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

static int
request_json(const char *port, const char *path, const char *body,
    char *response, size_t response_length)
{
	char	request[2048];
	int	length;

	length = snprintf(request, sizeof(request),
	    "POST %s HTTP/1.1\r\nHost: localhost\r\n"
	    "Content-Length: %zu\r\n\r\n%s", path, strlen(body), body);
	if (length < 0 || (size_t)length >= sizeof(request))
		return -1;
	return request_port(port, request, response, response_length);
}

static int
wait_for_proxy(const char *port, char *response, size_t length)
{
	struct timespec	delay;
	int		attempt;

	delay.tv_sec = 0;
	delay.tv_nsec = 10000000;
	for (attempt = 0; attempt < 200; attempt++) {
		if (request_port(port, "GET /health HTTP/1.1\r\n"
		    "Host: localhost\r\n\r\n", response, length) == 0)
			return 0;
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

int
main(void)
{
	char	path[] = "/tmp/oaioauthc-proxy-XXXXXX";
	char	base_url[128];
	char	mock_port[16];
	char	port[16];
	char	response[16384];
	pid_t	mock_pid;
	pid_t	pid;
	int	fd;
	int	result;
	int	slow_fd;
	int	status;

	pid = -1;
	mock_pid = -1;
	slow_fd = -1;
	result = 1;
	fd = mkstemp(path);
	REQUIRE(fd != -1);
	REQUIRE(close(fd) == 0);
	REQUIRE(write_private_file(path,
	    "{\"tokens\":{\"access_token\":\"access\","
	    "\"account_id\":\"acct_1\"}}") == 0);
	REQUIRE(reserve_port(port, sizeof(port)) == 0);
	REQUIRE(reserve_port(mock_port, sizeof(mock_port)) == 0);
	REQUIRE(snprintf(base_url, sizeof(base_url), "http://127.0.0.1:%s",
	    mock_port) < (int)sizeof(base_url));
	mock_pid = fork();
	REQUIRE(mock_pid != -1);
	if (mock_pid == 0)
		run_mock_upstream(mock_port);
	pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		execl("../src/oaioauthc", "oaioauthc", "serve", "--port", port,
		    "--oauth-file", path, "--base-url", base_url,
		    "--codex-version", "0.144.1", (char *)NULL);
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
	REQUIRE(request_port(port, "GET /v1/models HTTP/1.1\r\n"
	    "Host: localhost\r\n\r\n", response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"id\":\"gpt-test\"") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
	    "{\"model\":\"gpt-test\",\"input\":\"hi\"}", response,
	    sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"status\":\"completed\"") != NULL);
	REQUIRE(strstr(response, "\"text\":\"hello\"") != NULL);
	REQUIRE(request_json(port, "/v1/responses",
	    "{\"model\":\"gpt-test\",\"input\":\"hi\",\"stream\":true}",
	    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "response.output_text.delta") != NULL);
	REQUIRE(request_json(port, "/v1/chat/completions",
	    "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\","
	    "\"content\":\"hi\"}]}", response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"content\":\"hello\"") != NULL);
	REQUIRE(strstr(response, "\"prompt_tokens\":2") != NULL);
	REQUIRE(strstr(response, "\"cached_tokens\":1") != NULL);
	REQUIRE(request_json(port, "/v1/chat/completions",
	    "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\","
	    "\"content\":\"hi\"}],\"stream\":true}", response,
	    sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"content\":\"hello\"") != NULL);
	REQUIRE(strstr(response, "\"prompt_tokens\":2") != NULL);
	REQUIRE(strstr(response, "\"reasoning_tokens\":1") != NULL);
	REQUIRE(strstr(response, "data: [DONE]") != NULL);
	REQUIRE(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\ncontent-length: 2\r\n\r\n{}",
	    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	REQUIRE(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
	    "2\r\n{}\r\n0\r\n\r\n", response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	result = 0;

cleanup:
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
	return result;
}
