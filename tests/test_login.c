/*
** Process-level tests for the loopback OAuth login command.
**
** Tests drive the public executable through its IPv4 callback and a local
** token endpoint.  Pipes provide deterministic readiness handshakes before
** signals or callbacks are sent.  Every credential and token value is fake,
** and temporary files are removed after each scenario.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "util.h"

#define CALLBACK_PORT 1455
#define OUTPUT_SIZE   8192

#define REQUIRE(condition)                                                     \
	do {                                                                   \
		if (!(condition)) {                                            \
			(void)fprintf(stderr, "%s:%d: check failed: %s\n",     \
			    __FILE__, __LINE__, #condition);                   \
			goto cleanup;                                          \
		}                                                              \
	} while (0)

/* Sleep for a small deterministic test interval while tolerating signals. */
static void
delay_ms(long milliseconds)
{
	struct timespec delay;
	struct timespec remaining;

	delay.tv_sec = milliseconds / 1000;
	delay.tv_nsec = (milliseconds % 1000) * 1000000L;
	while (nanosleep(&delay, &remaining) == -1 && errno == EINTR)
		delay = remaining;
}

/* Reap child within timeout_ms, returning one for exit and zero for timeout. */
static int
wait_child(pid_t child, int *status, int timeout_ms)
{
	int attempts;
	int result;

	for (attempts = 0; attempts <= timeout_ms / 10; attempts++) {
		result = waitpid(child, status, WNOHANG);
		if (result == child)
			return 1;
		if (result == -1 && errno != EINTR)
			return -1;
		delay_ms(10);
	}
	return 0;
}

/* Read one readiness byte without allowing a failed mock to hang the suite. */
static int
wait_ready(int fd, int timeout_ms)
{
	struct pollfd descriptor;
	char	      ready;
	int	      result;

	descriptor.fd = fd;
	descriptor.events = POLLIN;
	descriptor.revents = 0;
	do {
		result = poll(&descriptor, 1, timeout_ms);
	} while (result == -1 && errno == EINTR);
	if (result != 1 || (descriptor.revents & POLLIN) == 0)
		return -1;
	return read(fd, &ready, sizeof(ready)) == sizeof(ready) ? 0 : -1;
}

/* Append available child diagnostics until expected text or pipe closure. */
static int
read_until(int fd, char *output, size_t length, size_t *used,
    const char *expected, int timeout_ms)
{
	struct pollfd descriptor;
	int	      attempts;
	int	      result;
	ssize_t	      count;

	descriptor.fd = fd;
	descriptor.events = POLLIN;
	for (attempts = 0; attempts <= timeout_ms / 10; attempts++) {
		output[*used] = '\0';
		if (expected != NULL && strstr(output, expected) != NULL)
			return 0;
		descriptor.revents = 0;
		result = poll(&descriptor, 1, 10);
		if (result == -1 && errno == EINTR)
			continue;
		if (result == -1)
			return -1;
		if (result == 0)
			continue;
		if ((descriptor.revents & (POLLIN | POLLHUP)) == 0)
			return -1;
		if (*used + 1 >= length)
			return -1;
		count = read(fd, output + *used, length - *used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return expected == NULL ? 0 : -1;
		*used += (size_t)count;
	}
	return -1;
}

/* Drain remaining diagnostics after the login child has closed its pipe. */
static int
drain_output(int fd, char *output, size_t length, size_t *used)
{
	ssize_t count;

	while (*used + 1 < length) {
		count = read(fd, output + *used, length - *used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count == 0)
			break;
		if (count == -1)
			return -1;
		*used += (size_t)count;
	}
	output[*used] = '\0';
	return 0;
}

/* Start login with stderr captured; token_url may be NULL before callbacks. */
static int
start_login(const char *timeout, const char *auth_path, const char *token_url,
    pid_t *child)
{
	int output_pipe[2];

	if (pipe(output_pipe) == -1)
		return -1;
	*child = fork();
	if (*child == -1) {
		close(output_pipe[0]);
		close(output_pipe[1]);
		return -1;
	}
	if (*child == 0) {
		close(output_pipe[0]);
		if (dup2(output_pipe[1], STDERR_FILENO) == -1)
			_exit(126);
		close(output_pipe[1]);
		if (token_url != NULL)
			execl("../src/oaioauthc", "oaioauthc", "login",
			    "--no-open", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-token-url",
			    token_url, (char *)NULL);
		else
			execl("../src/oaioauthc", "oaioauthc", "login",
			    "--no-open", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, (char *)NULL);
		_exit(127);
	}
	close(output_pipe[1]);
	return output_pipe[0];
}

/* Extract the generated OAuth state from one captured authorization URL. */
static int
extract_state(const char *output, char *state, size_t length)
{
	const char *cursor;
	const char *end;
	size_t	    state_length;

	cursor = strstr(output, "&state=");
	if (cursor == NULL)
		return -1;
	cursor += strlen("&state=");
	end = strchr(cursor, '&');
	if (end == NULL)
		return -1;
	state_length = (size_t)(end - cursor);
	if (state_length == 0 || state_length >= length)
		return -1;
	memcpy(state, cursor, state_length);
	state[state_length] = '\0';
	return 0;
}

/* Connect to the IPv4 loopback callback after its URL readiness message. */
static int
open_callback(void)
{
	struct sockaddr_in address;
	int		   fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(CALLBACK_PORT);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Send a valid state-bound callback and consume the small browser response. */
static int
send_callback(const char *state)
{
	char	request[512];
	char	response[512];
	int	fd;
	int	length;
	ssize_t count;

	fd = open_callback();
	if (fd == -1)
		return -1;
	length = snprintf(request, sizeof(request),
	    "GET /auth/callback?code=test-code&state=%s HTTP/1.1\r\n"
	    "Host: localhost\r\n\r\n",
	    state);
	if (length < 0 || (size_t)length >= sizeof(request) ||
	    write_all(fd, request, (size_t)length) == -1) {
		close(fd);
		return -1;
	}
	while ((count = read(fd, response, sizeof(response))) != 0) {
		if (count == -1 && errno == EINTR)
			continue;
		if (count == -1) {
			close(fd);
			return -1;
		}
	}
	return close(fd);
}

/* Bind a dynamic loopback token endpoint and return its URL. */
static int
open_token_listener(char *url, size_t length)
{
	struct sockaddr_in address;
	socklen_t	   address_length;
	int		   fd;
	int		   url_length;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    listen(fd, 1) == -1) {
		close(fd);
		return -1;
	}
	address_length = sizeof(address);
	if (getsockname(fd, (struct sockaddr *)&address, &address_length) ==
	    -1) {
		close(fd);
		return -1;
	}
	url_length = snprintf(url, length, "http://127.0.0.1:%u/token",
	    (unsigned int)ntohs(address.sin_port));
	if (url_length < 0 || (size_t)url_length >= length) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Serve one fake token exchange, optionally waiting to exercise cancellation. */
static void
run_token_server(int listen_fd, int ready_fd, int hold)
{
	static const char body[] =
	    "{\"access_token\":\"new-access\",\"account_id\":\"new-account\"}";
	char	request[2048];
	char	response[512];
	int	client_fd;
	int	length;
	ssize_t count;
	size_t	used;

	client_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (client_fd == -1)
		_exit(1);
	used = 0;
	while (used + 1 < sizeof(request)) {
		count =
		    read(client_fd, request + used, sizeof(request) - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			_exit(1);
		used += (size_t)count;
		request[used] = '\0';
		if (strstr(request, "\r\n\r\n") != NULL)
			break;
	}
	if (write_all(ready_fd, "1", 1) == -1)
		_exit(1);
	close(ready_fd);
	if (hold)
		delay_ms(5000);
	length = snprintf(response, sizeof(response),
	    "HTTP/1.1 200 OK\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: %zu\r\n"
	    "Connection: close\r\n\r\n%s",
	    strlen(body), body);
	if (length < 0 || (size_t)length >= sizeof(response) ||
	    write_all(client_fd, response, (size_t)length) == -1)
		_exit(1);
	close(client_fd);
	_exit(0);
}

/* Start one mock token endpoint with an accepted-request readiness pipe. */
static int
start_token_server(int hold, pid_t *child, int *ready_fd, char *url,
    size_t length)
{
	int listen_fd;
	int ready_pipe[2];

	listen_fd = open_token_listener(url, length);
	if (listen_fd == -1)
		return -1;
	if (pipe(ready_pipe) == -1) {
		close(listen_fd);
		return -1;
	}
	*child = fork();
	if (*child == -1) {
		close(listen_fd);
		close(ready_pipe[0]);
		close(ready_pipe[1]);
		return -1;
	}
	if (*child == 0) {
		close(ready_pipe[0]);
		run_token_server(listen_fd, ready_pipe[1], hold);
	}
	close(listen_fd);
	close(ready_pipe[1]);
	*ready_fd = ready_pipe[0];
	return 0;
}

/* Verify timeout, prompt refusal, and signal readiness without fixed sleeps. */
static int
test_basic_login(void)
{
	char   auth_path[128];
	char   existing_path[128];
	char   output[OUTPUT_SIZE];
	int    fd;
	int    output_fd;
	int    result;
	int    status;
	pid_t  child;
	size_t used;

	child = -1;
	output_fd = -1;
	result = 1;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-basic-%ld.json", (long)getpid());
	(void)snprintf(existing_path, sizeof(existing_path),
	    "/tmp/oaioauthc-login-existing-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	(void)unlink(existing_path);

	used = 0;
	output_fd = start_login("100", auth_path, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "timed out") != NULL);

	used = 0;
	output_fd = start_login("5000", auth_path, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(read_until(output_fd, output, sizeof(output), &used,
		    "OpenAI OAuth login URL", 2000) == 0);
	REQUIRE(kill(child, SIGTERM) == 0);
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "cancelled") != NULL);

	fd = open(existing_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	REQUIRE(fd != -1);
	REQUIRE(close(fd) == 0);
	used = 0;
	output_fd = start_login("5000", existing_path, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "interactive terminal") != NULL);
	result = 0;

cleanup:
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	(void)unlink(auth_path);
	(void)unlink(existing_path);
	return result;
}

/* Verify a slow byte stream cannot extend the callback request deadline. */
static int
test_slow_callback(void)
{
	char   auth_path[128];
	char   output[OUTPUT_SIZE];
	int    callback_fd;
	int    output_fd;
	int    result;
	int    status;
	int    write_index;
	int    child_exited;
	pid_t  child;
	size_t used;

	callback_fd = -1;
	child = -1;
	output_fd = -1;
	result = 1;
	used = 0;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-slow-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	output_fd = start_login("100", auth_path, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(read_until(output_fd, output, sizeof(output), &used,
		    "OpenAI OAuth login URL", 2000) == 0);
	callback_fd = open_callback();
	REQUIRE(callback_fd != -1);
	child_exited = 0;
	for (write_index = 0; write_index < 20; write_index++) {
		(void)write(callback_fd, "G", 1);
		child_exited = wait_child(child, &status, 0);
		if (child_exited != 0)
			break;
		delay_ms(60);
	}
	REQUIRE(child_exited == 1);
	child = -1;
	close(callback_fd);
	callback_fd = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "timed out reading callback request") != NULL);
	result = 0;

cleanup:
	if (callback_fd != -1)
		close(callback_fd);
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Verify SIGTERM aborts an in-flight token exchange without saving tokens. */
static int
test_exchange_cancellation(void)
{
	char   auth_path[128];
	char   output[OUTPUT_SIZE];
	char   state[128];
	char   token_url[128];
	int    output_fd;
	int    ready_fd;
	int    result;
	int    status;
	pid_t  child;
	pid_t  token_child;
	size_t used;

	child = -1;
	output_fd = -1;
	ready_fd = -1;
	result = 1;
	token_child = -1;
	used = 0;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-cancel-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	REQUIRE(start_token_server(1, &token_child, &ready_fd, token_url,
		    sizeof(token_url)) == 0);
	output_fd = start_login("5000", auth_path, token_url, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(read_until(output_fd, output, sizeof(output), &used,
		    "OpenAI OAuth login URL", 2000) == 0);
	REQUIRE(extract_state(output, state, sizeof(state)) == 0);
	REQUIRE(send_callback(state) == 0);
	REQUIRE(wait_ready(ready_fd, 2000) == 0);
	close(ready_fd);
	ready_fd = -1;
	REQUIRE(kill(child, SIGTERM) == 0);
	REQUIRE(wait_child(child, &status, 3000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "OAuth login cancelled") != NULL);
	REQUIRE(access(auth_path, F_OK) == -1 && errno == ENOENT);
	result = 0;

cleanup:
	if (ready_fd != -1)
		close(ready_fd);
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	if (token_child > 0) {
		(void)kill(token_child, SIGTERM);
		(void)waitpid(token_child, &status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Verify a file created after login starts is preserved without confirmation. */
static int
test_concurrent_auth_creation(void)
{
	static const char old_auth[] =
	    "{\"tokens\":{\"access_token\":\"old-access\","
	    "\"account_id\":\"old-account\"}}";
	char	      auth_path[128];
	char	      output[OUTPUT_SIZE];
	char	      state[128];
	char	      token_url[128];
	struct buffer saved;
	int	      output_fd;
	int	      ready_fd;
	int	      result;
	int	      status;
	int	      token_status;
	pid_t	      child;
	pid_t	      token_child;
	size_t	      used;

	child = -1;
	output_fd = -1;
	ready_fd = -1;
	result = 1;
	token_child = -1;
	used = 0;
	buffer_init(&saved);
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-race-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	REQUIRE(start_token_server(0, &token_child, &ready_fd, token_url,
		    sizeof(token_url)) == 0);
	output_fd = start_login("5000", auth_path, token_url, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(read_until(output_fd, output, sizeof(output), &used,
		    "OpenAI OAuth login URL", 2000) == 0);
	REQUIRE(extract_state(output, state, sizeof(state)) == 0);
	REQUIRE(write_private_file(auth_path, old_auth) == 0);
	REQUIRE(send_callback(state) == 0);
	REQUIRE(wait_ready(ready_fd, 2000) == 0);
	close(ready_fd);
	ready_fd = -1;
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(wait_child(token_child, &token_status, 2000) == 1);
	token_child = -1;
	REQUIRE(WIFEXITED(token_status) && WEXITSTATUS(token_status) == 0);
	REQUIRE(strstr(output, "appeared during login") != NULL);
	REQUIRE(read_file(auth_path, &saved) == 0);
	REQUIRE(strstr(saved.data, "old-access") != NULL);
	REQUIRE(strstr(saved.data, "new-access") == NULL);
	result = 0;

cleanup:
	buffer_free(&saved);
	if (ready_fd != -1)
		close(ready_fd);
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	if (token_child > 0) {
		(void)kill(token_child, SIGTERM);
		(void)waitpid(token_child, &status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Exercise every login deadline, cancellation, and overwrite regression. */
int
main(void)
{
	CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	CHECK(test_basic_login() == 0);
	CHECK(test_slow_callback() == 0);
	CHECK(test_exchange_cancellation() == 0);
	CHECK(test_concurrent_auth_creation() == 0);
	return 0;
}
