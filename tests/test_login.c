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

enum device_server_mode {
	DEVICE_SERVER_SUCCESS,
	DEVICE_SERVER_CONTROL_CODE,
	DEVICE_SERVER_EMBEDDED_NUL,
	DEVICE_SERVER_INCOMPLETE_TOKENS,
	DEVICE_SERVER_HANG
};

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
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--no-open", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-token-url",
			    token_url, (char *)NULL);
		else
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--no-open", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, (char *)NULL);
		_exit(127);
	}
	close(output_pipe[1]);
	return output_pipe[0];
}

/* Read one bounded HTTP request and return its request-target path. */
static int
read_http_request(int fd, char *request, size_t length, char *path,
    size_t path_length)
{
	char   *headers;
	char   *value;
	char	target[256];
	size_t	content_length;
	size_t	header_length;
	size_t	used;
	ssize_t count;

	used = 0;
	headers = NULL;
	while (used + 1 < length) {
		count = read(fd, request + used, length - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		used += (size_t)count;
		request[used] = '\0';
		headers = strstr(request, "\r\n\r\n");
		if (headers != NULL)
			break;
	}
	if (headers == NULL)
		return -1;
	header_length = (size_t)(headers - request) + 4;
	content_length = 0;
	value = strstr(request, "\r\nContent-Length:");
	if (value != NULL &&
	    sscanf(value + 2, "Content-Length: %zu", &content_length) != 1)
		return -1;
	if (content_length > length - header_length - 1)
		return -1;
	while (used < header_length + content_length) {
		count = read(fd, request + used, length - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		used += (size_t)count;
	}
	request[used] = '\0';
	if (sscanf(request, "%*s %255s", target) != 1 ||
	    strlen(target) >= path_length)
		return -1;
	(void)strcpy(path, target);
	return 0;
}

/* Send one deterministic JSON response from the device-flow mock. */
static int
send_device_response_bytes(int fd, int status, const void *body,
    size_t body_length)
{
	char header[256];
	int  header_length;

	header_length = snprintf(header, sizeof(header),
	    "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
	    "Content-Length: %zu\r\nConnection: close\r\n\r\n",
	    status, status == 200 ? "OK" : "Pending", body_length);
	if (header_length < 0 || (size_t)header_length >= sizeof(header) ||
	    write_all(fd, header, (size_t)header_length) == -1)
		return -1;
	return write_all(fd, body, body_length);
}

/* Send one NUL-free deterministic JSON response from the device-flow mock. */
static int
send_device_response(int fd, int status, const char *body)
{
	return send_device_response_bytes(fd, status, body, strlen(body));
}

/* Serve the exact four-request device authorization protocol sequence. */
static void
run_device_server(int listen_fd, enum device_server_mode mode)
{
	static const char control_code[] =
	    "{\"device_auth_id\":\"device-id\","
	    "\"user_code\":\"ABCD-\\u001bEFGH\",\"interval\":\"0\"}";
	static const char embedded_nul[] =
	    "{\"device_auth_id\":\"device-id\","
	    "\"user_code\":\"ABCD-EFGH\",\"interval\":\"0\"}\0{}";
	static const char usercode[] =
	    "{\"device_auth_id\":\"device-id\","
	    "\"user_code\":\"ABCD-EFGH\",\"interval\":\" 0 \"}";
	static const char pending[] = "{}";
	static const char approved[] =
	    "{\"authorization_code\":\"auth-code\","
	    "\"code_challenge\":"
	    "\"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\","
	    "\"code_verifier\":"
	    "\"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\"}";
	static const char tokens[] = "{\"access_token\":\"device-access\","
				     "\"refresh_token\":\"device-refresh\","
				     "\"id_token\":\"device-id-token\","
				     "\"account_id\":\"device-account\"}";
	static const char incomplete_tokens[] =
	    "{\"access_token\":\"device-access\","
	    "\"account_id\":\"device-account\"}";
	char request[8192];
	char path[256];
	int  client_fd;
	int  index;
	int  status;

	if (mode != DEVICE_SERVER_SUCCESS &&
	    mode != DEVICE_SERVER_INCOMPLETE_TOKENS) {
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1 ||
		    read_http_request(client_fd, request, sizeof(request), path,
			sizeof(path)) == -1)
			_exit(4);
		if (mode == DEVICE_SERVER_HANG) {
			delay_ms(5000);
			status = 0;
		} else if (mode == DEVICE_SERVER_CONTROL_CODE)
			status =
			    send_device_response(client_fd, 200, control_code);
		else
			status = send_device_response_bytes(client_fd, 200,
			    embedded_nul, sizeof(embedded_nul) - 1);
		close(client_fd);
		close(listen_fd);
		_exit(status == 0 ? 0 : 5);
	}
	for (index = 0; index < 4; index++) {
		client_fd = accept(listen_fd, NULL, NULL);
		if (client_fd == -1)
			_exit(1);
		if (read_http_request(client_fd, request, sizeof(request), path,
			sizeof(path)) == -1)
			_exit(2);
		status = 200;
		if (index == 0 &&
		    strcmp(path, "/api/accounts/deviceauth/usercode") == 0 &&
		    strstr(request, "\"client_id\":\"client&id+value\"") !=
			NULL)
			status = send_device_response(client_fd, 200, usercode);
		else if ((index == 1 || index == 2) &&
		    strcmp(path, "/api/accounts/deviceauth/token") == 0)
			status = send_device_response(client_fd,
			    index == 1 ? 404 : 200,
			    index == 1 ? pending : approved);
		else if (index == 3 && strcmp(path, "/oauth/token") == 0 &&
		    strstr(request, "client_id=client%26id%2Bvalue") != NULL)
			status = send_device_response(client_fd, 200,
			    mode == DEVICE_SERVER_INCOMPLETE_TOKENS
				? incomplete_tokens
				: tokens);
		else
			status = -1;
		close(client_fd);
		if (status == -1)
			_exit(3);
	}
	close(listen_fd);
	_exit(0);
}

/* Bind one issuer mock and expose both its root and token endpoint URLs. */
static int
open_device_listener(char *issuer, size_t issuer_length, char *token_url,
    size_t token_length)
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
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    listen(fd, 4) == -1) {
		close(fd);
		return -1;
	}
	address_length = sizeof(address);
	if (getsockname(fd, (struct sockaddr *)&address, &address_length) ==
	    -1) {
		close(fd);
		return -1;
	}
	result = snprintf(issuer, issuer_length, "http://127.0.0.1:%u",
	    (unsigned int)ntohs(address.sin_port));
	if (result < 0 || (size_t)result >= issuer_length) {
		close(fd);
		return -1;
	}
	result = snprintf(token_url, token_length, "%s/oauth/token", issuer);
	if (result < 0 || (size_t)result >= token_length) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Start the device mock in a child before launching the login process. */
static int
start_device_server(pid_t *child, char *issuer, size_t issuer_length,
    char *token_url, size_t token_length, enum device_server_mode mode)
{
	int listen_fd;

	listen_fd = open_device_listener(issuer, issuer_length, token_url,
	    token_length);
	if (listen_fd == -1)
		return -1;
	*child = fork();
	if (*child == -1) {
		close(listen_fd);
		return -1;
	}
	if (*child == 0)
		run_device_server(listen_fd, mode);
	close(listen_fd);
	return 0;
}

/* Start --device-auth with captured diagnostics and an explicit local
** issuer. */
static int
start_device_login(const char *timeout, const char *auth_path,
    const char *issuer, const char *token_url, const char *client_id,
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
		if (token_url != NULL && client_id != NULL)
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--device-auth", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-issuer", issuer,
			    "--oauth-token-url", token_url, "--oauth-client-id",
			    client_id, (char *)NULL);
		else if (token_url != NULL)
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--device-auth", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-issuer", issuer,
			    "--oauth-token-url", token_url, (char *)NULL);
		else if (client_id != NULL)
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--device-auth", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-issuer", issuer,
			    "--oauth-client-id", client_id, (char *)NULL);
		else
			execl(TEST_PROGRAM_PATH, "oaioauthc", "login",
			    "--device-auth", "--login-timeout-ms", timeout,
			    "--oauth-file", auth_path, "--oauth-issuer", issuer,
			    (char *)NULL);
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
	    "{\"access_token\":\"new-access\",\"refresh_token\":\"new-refresh\","
	    "\"id_token\":\"new-id\",\"account_id\":\"new-account\"}";
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

/* Reject custom issuers that would send OAuth credentials over the network. */
static int
test_unsafe_issuer(void)
{
	char   auth_path[128];
	char   output[OUTPUT_SIZE];
	int    output_fd;
	int    result;
	int    status;
	pid_t  child;
	size_t used;

	child = -1;
	output_fd = -1;
	result = 1;
	used = 0;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-issuer-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	output_fd = start_device_login("500", auth_path, "http://example.com",
	    NULL, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "invalid OAuth issuer") != NULL);
	REQUIRE(access(auth_path, F_OK) == -1 && errno == ENOENT);
	result = 0;

cleanup:
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Reject device responses containing terminal controls or hidden binary data. */
static int
test_rejected_device_response(enum device_server_mode mode,
    const char					     *expected)
{
	char   auth_path[128];
	char   issuer[128];
	char   output[OUTPUT_SIZE];
	char   token_url[160];
	int    output_fd;
	int    result;
	int    server_status;
	int    status;
	pid_t  child;
	pid_t  server_child;
	size_t used;

	child = -1;
	server_child = -1;
	output_fd = -1;
	result = 1;
	used = 0;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-reject-%d-%ld.json", (int)mode,
	    (long)getpid());
	(void)unlink(auth_path);
	REQUIRE(start_device_server(&server_child, issuer, sizeof(issuer),
		    token_url, sizeof(token_url), mode) == 0);
	output_fd = start_device_login("2000", auth_path, issuer, NULL,
	    mode == DEVICE_SERVER_INCOMPLETE_TOKENS ? "client&id+value" : NULL,
	    &child);
	REQUIRE(output_fd != -1);
	REQUIRE(wait_child(child, &status, 3000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, expected) != NULL);
	REQUIRE(wait_child(server_child, &server_status, 2000) == 1);
	server_child = -1;
	REQUIRE(WIFEXITED(server_status) && WEXITSTATUS(server_status) == 0);
	REQUIRE(access(auth_path, F_OK) == -1 && errno == ENOENT);
	result = 0;

cleanup:
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	if (server_child > 0) {
		(void)kill(server_child, SIGKILL);
		(void)waitpid(server_child, &server_status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Bound the initial user-code HTTP request by the overall login deadline. */
static int
test_device_request_timeout(void)
{
	char   auth_path[128];
	char   issuer[128];
	char   output[OUTPUT_SIZE];
	char   token_url[160];
	int    output_fd;
	int    result;
	int    server_status;
	int    status;
	pid_t  child;
	pid_t  server_child;
	size_t used;

	child = -1;
	server_child = -1;
	output_fd = -1;
	result = 1;
	used = 0;
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-device-timeout-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	REQUIRE(start_device_server(&server_child, issuer, sizeof(issuer),
		    token_url, sizeof(token_url), DEVICE_SERVER_HANG) == 0);
	output_fd =
	    start_device_login("100", auth_path, issuer, NULL, NULL, &child);
	REQUIRE(output_fd != -1);
	REQUIRE(wait_child(child, &status, 2000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 1);
	REQUIRE(strstr(output, "Timeout was reached") != NULL ||
	    strstr(output, "timed out") != NULL);
	REQUIRE(access(auth_path, F_OK) == -1 && errno == ENOENT);
	result = 0;

cleanup:
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	if (server_child > 0) {
		(void)kill(server_child, SIGKILL);
		(void)waitpid(server_child, &server_status, 0);
	}
	(void)unlink(auth_path);
	return result;
}

/* Verify device authorization prints the code, polls, exchanges, and saves. */
static int
test_device_login(void)
{
	char	      auth_path[128];
	char	      issuer[128];
	char	      token_url[160];
	char	      output[OUTPUT_SIZE];
	struct buffer saved;
	int	      output_fd;
	int	      result;
	int	      status;
	int	      server_status;
	pid_t	      child;
	pid_t	      server_child;
	size_t	      issuer_used;
	size_t	      used;

	child = -1;
	server_child = -1;
	output_fd = -1;
	result = 1;
	used = 0;
	buffer_init(&saved);
	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-device-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	REQUIRE(start_device_server(&server_child, issuer, sizeof(issuer),
		    token_url, sizeof(token_url), DEVICE_SERVER_SUCCESS) == 0);
	issuer_used = strlen(issuer);
	REQUIRE(issuer_used + 1 < sizeof(issuer));
	issuer[issuer_used] = '/';
	issuer[issuer_used + 1] = '\0';
	output_fd = start_device_login("5000", auth_path, issuer, NULL,
	    "client&id+value", &child);
	REQUIRE(output_fd != -1);
	REQUIRE(read_until(output_fd, output, sizeof(output), &used,
		    "OpenAI device authorization code: ABCD-EFGH", 2000) == 0);
	REQUIRE(strstr(output,
		    "Continue only if you started this login in oaioauthc") !=
	    NULL);
	REQUIRE(wait_child(child, &status, 5000) == 1);
	child = -1;
	REQUIRE(drain_output(output_fd, output, sizeof(output), &used) == 0);
	close(output_fd);
	output_fd = -1;
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	REQUIRE(wait_child(server_child, &server_status, 2000) == 1);
	server_child = -1;
	REQUIRE(WIFEXITED(server_status) && WEXITSTATUS(server_status) == 0);
	REQUIRE(read_file(auth_path, &saved) == 0);
	REQUIRE(strstr(saved.data, "device-access") != NULL);
	REQUIRE(strstr(saved.data, "device-account") != NULL);
	result = 0;

cleanup:
	buffer_free(&saved);
	if (output_fd != -1)
		close(output_fd);
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, &status, 0);
	}
	if (server_child > 0) {
		(void)kill(server_child, SIGKILL);
		(void)waitpid(server_child, &server_status, 0);
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
	CHECK(test_unsafe_issuer() == 0);
	CHECK(test_rejected_device_response(DEVICE_SERVER_CONTROL_CODE,
		  "invalid required fields") == 0);
	CHECK(test_rejected_device_response(DEVICE_SERVER_EMBEDDED_NUL,
		  "invalid JSON") == 0);
	CHECK(test_rejected_device_response(DEVICE_SERVER_INCOMPLETE_TOKENS,
		  "missing initial OAuth credentials") == 0);
	CHECK(test_device_request_timeout() == 0);
	CHECK(test_device_login() == 0);
	return 0;
}
