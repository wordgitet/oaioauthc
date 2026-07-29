/*
 * Local failure-path process tests.
 *
 * These tests execute the public binary against deterministic loopback peers.
 * They verify invalid local configuration fails cleanly and that a slow model
 * catalog refresh does not stall the parent listener.  Temporary credentials,
 * child processes, and sockets are released on every completed scenario.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "util.h"

/* Reserve one unused loopback port for a child process. */
static int
reserve_port(char *port, size_t length)
{
	struct sockaddr_in address;
	socklen_t	   address_length;
	int		   fd;
	int		   result;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);
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
	return (result);
}

/* Bind a deterministic loopback mock to a reserved port. */
static int
listen_port(const char *port)
{
	struct sockaddr_in address;
	int		   fd;
	int		   one;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);
	one = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons((unsigned short)atoi(port));
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    listen(fd, 4) == -1) {
		close(fd);
		return (-1);
	}
	return (fd);
}

/* Read one complete header-only request from the proxy. */
static int
read_headers(int fd)
{
	char	buffer[4096];
	size_t	used;
	ssize_t count;

	used = 0;
	while (used + 1 < sizeof(buffer)) {
		count = read(fd, buffer + used, sizeof(buffer) - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return (-1);
		used += (size_t)count;
		buffer[used] = '\0';
		if (strstr(buffer, "\r\n\r\n") != NULL)
			return (0);
	}
	return (-1);
}

/* Send one fixed-length mock response. */
static int
send_response(int fd, int status, const char *body)
{
	char header[256];
	int  length;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 %d Test\r\nContent-Type: application/json\r\n"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
	    status, strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header) ||
	    write_all(fd, header, (size_t)length) == -1)
		return (-1);
	return (write_all(fd, body, strlen(body)));
}

/*
** Fail startup catalog warming, then hold the asynchronous retry for two seconds.
**
** slow_fd tells the test exactly when the refresh child is blocked, making the
** listener-latency assertion deterministic.
*/
static void
run_slow_catalog_mock(const char *port, int ready_fd, int slow_fd)
{
	static const char models[] = "{\"models\":[{\"slug\":\"gpt-test\"}]}";
	struct timespec	  delay;
	int		  client;
	int		  listener;

	listener = listen_port(port);
	if (listener == -1 || write_all(ready_fd, "R", 1) == -1)
		_exit(10);
	client = accept(listener, NULL, NULL);
	if (client == -1 || read_headers(client) == -1 ||
	    send_response(client, 503, "{}") == -1)
		_exit(11);
	close(client);
	client = accept(listener, NULL, NULL);
	if (client == -1 || read_headers(client) == -1 ||
	    write_all(slow_fd, "S", 1) == -1)
		_exit(12);
	delay.tv_sec = 2;
	delay.tv_nsec = 0;
	while (nanosleep(&delay, &delay) == -1 && errno == EINTR)
		continue;
	if (send_response(client, 200, models) == -1)
		_exit(13);
	close(client);
	close(listener);
	_exit(0);
}

/* Connect one request client to a loopback proxy. */
static int
request_health(const char *port, char *response, size_t length)
{
	struct sockaddr_in address;
	static const char  request[] =
	    "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
	size_t	used;
	ssize_t count;
	int	fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons((unsigned short)atoi(port));
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    write_all(fd, request, sizeof(request) - 1) == -1) {
		close(fd);
		return (-1);
	}
	used = 0;
	while (used + 1 < length &&
	    (count = read(fd, response + used, length - used - 1)) > 0)
		used += (size_t)count;
	response[used] = '\0';
	close(fd);
	return (0);
}

/* Wait until the proxy accepts and answers its local health route. */
static int
wait_for_proxy(const char *port, char *response, size_t length)
{
	struct timespec delay;
	int		attempt;

	delay.tv_sec = 0;
	delay.tv_nsec = 10000000;
	for (attempt = 0; attempt < 200; attempt++) {
		if (request_health(port, response, length) == 0)
			return (0);
		(void)nanosleep(&delay, NULL);
	}
	return (-1);
}

/* Confirm an empty base URL is rejected before listener or upstream work. */
static int
test_empty_base_url(void)
{
	char	output[512];
	size_t	used;
	ssize_t count;
	int	descriptors[2];
	int	status;
	pid_t	pid;

	if (pipe(descriptors) == -1)
		return (-1);
	pid = fork();
	if (pid == 0) {
		close(descriptors[0]);
		if (dup2(descriptors[1], STDERR_FILENO) == -1)
			_exit(126);
		close(descriptors[1]);
		execl(TEST_PROGRAM_PATH, "oaioauthc", "serve", "--base-url", "",
		    "--codex-version", "9.9.9", "--models", "gpt-test",
		    (char *)NULL);
		_exit(127);
	}
	close(descriptors[1]);
	if (pid == -1)
		return (-1);
	used = 0;
	while (used + 1 < sizeof(output) &&
	    (count = read(descriptors[0], output + used,
		 sizeof(output) - used - 1)) > 0)
		used += (size_t)count;
	output[used] = '\0';
	close(descriptors[0]);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 1)
		return (-1);
	return (
	    strstr(output, "--base-url must not be empty") == NULL ? -1 : 0);
}

/* Reject plaintext remote credential endpoints before listener startup. */
static int
test_unsafe_endpoints(void)
{
	if (url_is_secure_or_loopback("https://example.com/api") == 0 ||
	    url_is_secure_or_loopback("http://localhost:8080/api") == 0 ||
	    url_is_secure_or_loopback("http://127.0.0.1:8080/api") == 0 ||
	    url_is_secure_or_loopback("http://[::1]:8080/api") == 0)
		return (-1);
	if (url_is_secure_or_loopback("http://example.com/api") ||
	    url_is_secure_or_loopback("http://localhost.evil/api") ||
	    url_is_secure_or_loopback("http://localhost:/api") ||
	    url_is_secure_or_loopback("https://user@example.com/api") ||
	    url_is_secure_or_loopback("https://example.com/\napi"))
		return (-1);
	return (0);
}

/* Confirm a slow parent catalog retry does not delay a second health request. */
static int
test_async_catalog_refresh(void)
{
	struct timespec started;
	struct timespec ended;
	char		path[] = "/tmp/oaioauthc-local-XXXXXX";
	char		base_url[128];
	char		mock_port[16];
	char		proxy_port[16];
	char		response[1024];
	char		byte;
	long		elapsed_ms;
	int		fd;
	int		mock_ready[2];
	int		slow_started[2];
	int		status;
	int		result;
	pid_t		mock;
	pid_t		proxy;

	mock = -1;
	proxy = -1;
	result = -1;
	mock_ready[0] = -1;
	mock_ready[1] = -1;
	slow_started[0] = -1;
	slow_started[1] = -1;
	fd = mkstemp(path);
	if (fd == -1 || close(fd) == -1 ||
	    write_private_file(path,
		"{\"tokens\":{\"access_token\":\"access\","
		"\"account_id\":\"acct_test\"}}") == -1 ||
	    reserve_port(mock_port, sizeof(mock_port)) == -1 ||
	    reserve_port(proxy_port, sizeof(proxy_port)) == -1 ||
	    pipe(mock_ready) == -1 || pipe(slow_started) == -1)
		goto cleanup;
	if (snprintf(base_url, sizeof(base_url), "http://127.0.0.1:%s",
		mock_port) >= (int)sizeof(base_url))
		goto cleanup;
	mock = fork();
	if (mock == 0) {
		close(mock_ready[0]);
		close(slow_started[0]);
		run_slow_catalog_mock(mock_port, mock_ready[1],
		    slow_started[1]);
	}
	if (mock == -1)
		goto cleanup;
	close(mock_ready[1]);
	mock_ready[1] = -1;
	if (read(mock_ready[0], &byte, 1) != 1)
		goto cleanup;
	close(mock_ready[0]);
	mock_ready[0] = -1;
	proxy = fork();
	if (proxy == 0) {
		fd = open("/dev/null", O_WRONLY);
		if (fd == -1 || dup2(fd, STDERR_FILENO) == -1)
			_exit(126);
		close(fd);
		execl(TEST_PROGRAM_PATH, "oaioauthc", "serve", "--port",
		    proxy_port, "--oauth-file", path, "--base-url", base_url,
		    "--codex-version", "9.9.9", (char *)NULL);
		_exit(127);
	}
	if (proxy == -1 ||
	    wait_for_proxy(proxy_port, response, sizeof(response)) == -1 ||
	    strstr(response, "200 OK") == NULL)
		goto cleanup;
	close(slow_started[1]);
	slow_started[1] = -1;
	if (read(slow_started[0], &byte, 1) != 1 ||
	    clock_gettime(CLOCK_MONOTONIC, &started) == -1 ||
	    request_health(proxy_port, response, sizeof(response)) == -1 ||
	    clock_gettime(CLOCK_MONOTONIC, &ended) == -1)
		goto cleanup;
	elapsed_ms = (ended.tv_sec - started.tv_sec) * 1000L +
	    (ended.tv_nsec - started.tv_nsec) / 1000000L;
	if (strstr(response, "200 OK") == NULL || elapsed_ms >= 1000)
		goto cleanup;
	if (waitpid(mock, &status, 0) != mock || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		goto cleanup;
	mock = -1;
	result = 0;

cleanup:
	if (mock_ready[0] != -1)
		close(mock_ready[0]);
	if (mock_ready[1] != -1)
		close(mock_ready[1]);
	if (slow_started[0] != -1)
		close(slow_started[0]);
	if (slow_started[1] != -1)
		close(slow_started[1]);
	if (proxy > 0) {
		(void)kill(proxy, SIGTERM);
		(void)waitpid(proxy, &status, 0);
	}
	if (mock > 0) {
		(void)kill(mock, SIGTERM);
		(void)waitpid(mock, &status, 0);
	}
	(void)unlink(path);
	return (result);
}

int
main(void)
{
	(void)signal(SIGPIPE, SIG_IGN);
	CHECK(test_empty_base_url() == 0);
	CHECK(test_unsafe_endpoints() == 0);
	CHECK(test_async_catalog_refresh() == 0);
	return (0);
}
