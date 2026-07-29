/*
 * Focused tests for Codex auth.json parsing, JWT account discovery, refresh
 * eligibility, PKCE request construction, and serialized refreshes against a
 * deterministic local OAuth mock.  They never contact a real OAuth service.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "auth.h"
#include "test.h"
#include "util.h"

/* Read one complete small libcurl request from the local token mock. */
static int
read_token_request(int fd)
{
	char	buffer[8192];
	char   *headers;
	char   *value;
	size_t	content_length;
	size_t	header_length;
	size_t	used;
	ssize_t count;

	used = 0;
	headers = NULL;
	while (used + 1 < sizeof(buffer)) {
		count = read(fd, buffer + used, sizeof(buffer) - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return (-1);
		used += (size_t)count;
		buffer[used] = '\0';
		headers = strstr(buffer, "\r\n\r\n");
		if (headers != NULL)
			break;
	}
	if (headers == NULL)
		return (-1);
	header_length = (size_t)(headers - buffer) + 4;
	value = strstr(buffer, "\r\nContent-Length:");
	if (value == NULL ||
	    sscanf(value + sizeof("\r\nContent-Length:") - 1, "%zu",
		&content_length) != 1)
		return (-1);
	while (used < header_length + content_length) {
		count = read(fd, buffer + used, sizeof(buffer) - used);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			return (-1);
		used += (size_t)count;
	}
	return (0);
}

/* Return one complete OAuth token response from the local mock. */
static int
send_token_response(int fd, const char *access_token, const char *refresh_token)
{
	char body[256];
	char header[256];
	int  body_length;
	int  header_length;

	body_length = snprintf(body, sizeof(body),
	    "{\"access_token\":\"%s\",\"refresh_token\":\"%s\","
	    "\"account_id\":\"acct_test\"}",
	    access_token, refresh_token);
	if (body_length < 0 || (size_t)body_length >= sizeof(body))
		return (-1);
	header_length = snprintf(header, sizeof(header),
	    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
	    "Content-Length: %d\r\nConnection: close\r\n\r\n",
	    body_length);
	if (header_length < 0 || (size_t)header_length >= sizeof(header) ||
	    write_all(fd, header, (size_t)header_length) == -1)
		return (-1);
	return (write_all(fd, body, (size_t)body_length));
}

/*
** Hold the first refresh request while checking whether another reaches OAuth.
**
** Correct locking permits only one request.  Without it, both workers exchange
** the old refresh token and the delayed first response can overwrite the newer
** result written by the second worker.
*/
static void
run_token_mock(int listener, int ready_fd, int start_fd)
{
	struct pollfd descriptor;
	char	      byte;
	int	      first;
	int	      second;

	first = accept(listener, NULL, NULL);
	if (first == -1 || read_token_request(first) == -1 ||
	    write_all(ready_fd, "R", 1) == -1 || read(start_fd, &byte, 1) != 1)
		_exit(10);
	descriptor.fd = listener;
	descriptor.events = POLLIN;
	descriptor.revents = 0;
	if (poll(&descriptor, 1, 1000) == -1)
		_exit(11);
	if ((descriptor.revents & POLLIN) != 0) {
		second = accept(listener, NULL, NULL);
		if (second == -1 || read_token_request(second) == -1 ||
		    send_token_response(second, "access_newest",
			"refresh_newest") == -1)
			_exit(12);
		close(second);
		if (send_token_response(first, "access_stale",
			"refresh_stale") == -1)
			_exit(13);
		close(first);
		_exit(20);
	}
	if (send_token_response(first, "access_first", "refresh_first") == -1)
		_exit(14);
	close(first);
	close(listener);
	_exit(0);
}

/* Load the shared auth file, synchronize startup, then perform one refresh. */
static void
run_refresh_worker(const char *path, const char *url, int ready_fd,
    int start_fd)
{
	struct auth_session session;
	char		    error[256];
	char		    byte;
	int		    result;

	result = auth_load(path, &session, error, sizeof(error));
	if (ready_fd != -1 &&
	    (write_all(ready_fd, "R", 1) == -1 ||
		read(start_fd, &byte, 1) != 1))
		result = -1;
	if (result == 0)
		result = auth_refresh(path, "client", url, &session, error,
		    sizeof(error));
	auth_session_free(&session);
	_exit(result == 0 ? 0 : 30);
}

/* Reap one child and require a successful normal exit. */
static int
wait_success(pid_t *pid)
{
	int   status;
	pid_t result;

	result = waitpid(*pid, &status, 0);
	if (result == *pid)
		*pid = -1;
	return (result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0
		? 0
		: -1);
}

/* Terminate and reap a test child that remains active after a failed check. */
static void
stop_child(pid_t pid)
{
	if (pid <= 0)
		return;
	(void)kill(pid, SIGTERM);
	while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
		continue;
}

/* Close both initialized ends of a test synchronization pipe. */
static void
close_pipe(int descriptors[2])
{
	if (descriptors[0] != -1)
		close(descriptors[0]);
	if (descriptors[1] != -1)
		close(descriptors[1]);
}

/* Verify waiting refresh workers reload the token saved by the lock holder. */
static int
test_refresh_serialization(void)
{
	struct sockaddr_in  address;
	struct auth_session session;
	socklen_t	    address_length;
	char		    error[256];
	char		    lock_path[160];
	char		    path[] = "/tmp/oaioauthc-refresh-test-XXXXXX";
	char		    url[128];
	char		    byte;
	int		    fd;
	int		    listener;
	int		    mock_ready[2] = { -1, -1 };
	int		    mock_start[2] = { -1, -1 };
	int		    worker_ready[2] = { -1, -1 };
	int		    worker_start[2] = { -1, -1 };
	int		    result;
	int		    session_loaded;
	pid_t		    mock;
	pid_t		    first;
	pid_t		    second;

	listener = -1;
	mock = -1;
	first = -1;
	second = -1;
	result = -1;
	session_loaded = 0;
	lock_path[0] = '\0';
	fd = mkstemp(path);
	if (fd == -1 || close(fd) == -1)
		goto cleanup;
	(void)snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
	if (write_private_file(path,
		"{\"tokens\":{\"access_token\":\"access_old\","
		"\"refresh_token\":\"refresh_old\","
		"\"account_id\":\"acct_test\"},"
		"\"last_refresh\":\"1970-01-01T00:00:00Z\"}") == -1)
		goto cleanup;
	listener = socket(AF_INET, SOCK_STREAM, 0);
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (listener == -1 ||
	    bind(listener, (struct sockaddr *)&address, sizeof(address)) ==
		-1 ||
	    listen(listener, 2) == -1)
		goto cleanup;
	address_length = sizeof(address);
	if (getsockname(listener, (struct sockaddr *)&address,
		&address_length) == -1)
		goto cleanup;
	(void)snprintf(url, sizeof(url), "http://127.0.0.1:%u/token",
	    (unsigned int)ntohs(address.sin_port));
	if (pipe(mock_ready) == -1 || pipe(mock_start) == -1 ||
	    pipe(worker_ready) == -1 || pipe(worker_start) == -1)
		goto cleanup;
	mock = fork();
	if (mock == 0)
		run_token_mock(listener, mock_ready[1], mock_start[0]);
	if (mock == -1)
		goto cleanup;
	first = fork();
	if (first == 0)
		run_refresh_worker(path, url, -1, -1);
	if (first == -1 || read(mock_ready[0], &byte, 1) != 1)
		goto cleanup;
	second = fork();
	if (second == 0)
		run_refresh_worker(path, url, worker_ready[1], worker_start[0]);
	if (second == -1 || read(worker_ready[0], &byte, 1) != 1 ||
	    write_all(worker_start[1], "G", 1) == -1 ||
	    write_all(mock_start[1], "G", 1) == -1)
		goto cleanup;
	close(listener);
	listener = -1;
	if (wait_success(&first) == -1 || wait_success(&second) == -1 ||
	    wait_success(&mock) == -1)
		goto cleanup;
	if (auth_load(path, &session, error, sizeof(error)) == -1)
		goto cleanup;
	session_loaded = 1;
	result = session.refresh_token != NULL &&
		strcmp(session.refresh_token, "refresh_first") == 0
	    ? 0
	    : -1;

cleanup:
	if (session_loaded)
		auth_session_free(&session);
	if (listener != -1)
		close(listener);
	close_pipe(mock_ready);
	close_pipe(mock_start);
	close_pipe(worker_ready);
	close_pipe(worker_start);
	stop_child(first);
	stop_child(second);
	stop_child(mock);
	(void)unlink(path);
	if (lock_path[0] != '\0')
		(void)unlink(lock_path);
	return (result);
}

/*
** Exercise both explicit and JWT-derived account ids, opaque-token refresh
** fallback, and PKCE construction.  The temporary auth file is private and
** removed before exit so the test never depends on a developer's real session.
*/
int
main(void)
{
	char		     path[128];
	char		     error[256];
	struct auth_session  session;
	struct oauth_request request;

	(void)snprintf(path, sizeof(path), "/tmp/oaioauthc-test-%ld.json",
	    (long)getpid());
	CHECK(write_private_file(path,
		  "{\"tokens\":{\"access_token\":\"access\","
		  "\"refresh_token\":\"refresh\",\"id_token\":\"id\","
		  "\"account_id\":\"acct_1\"}}") == 0);
	CHECK(auth_load(path, &session, error, sizeof(error)) == 0);
	CHECK(strcmp(session.access_token, "access") == 0);
	CHECK(strcmp(session.account_id, "acct_1") == 0);
	auth_session_free(&session);
	CHECK(write_private_file(path,
		  "{\"tokens\":{\"access_token\":\"header."
		  "eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9"
		  "hY2NvdW50X2lkIjoiYWNjdF9qd3QifX0.signature\"}}") == 0);
	CHECK(auth_load(path, &session, error, sizeof(error)) == 0);
	CHECK(strcmp(session.account_id, "acct_jwt") == 0);
	auth_session_free(&session);
	memset(&session, 0, sizeof(session));
	session.access_token = oaio_strdup("opaque");
	session.refresh_token = oaio_strdup("refresh");
	session.last_refresh = oaio_strdup("1970-01-01T00:00:00Z");
	CHECK(auth_session_needs_refresh(&session) == 1);
	free(session.last_refresh);
	session.last_refresh = NULL;
	CHECK(auth_session_needs_refresh(&session) == 1);
	auth_session_free(&session);
	memset(&request, 0, sizeof(request));
	CHECK(oauth_request_create(NULL, "http://localhost:1455/auth/callback",
		  NULL, &request, error, sizeof(error)) == 0);
	CHECK(strstr(request.authorization_url, "code_challenge_method=S256") !=
	    NULL);
	CHECK(request.state != NULL && request.code_verifier != NULL);
	oauth_request_free(&request);
	CHECK(test_refresh_serialization() == 0);
	(void)unlink(path);
	return 0;
}
