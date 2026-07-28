/*
**
** Process-level tests for detached daemon startup and local control.
**
** Every scenario uses an explicit model and Codex version, so no credential
** file or network request is needed.  The test owns the temporary runtime
** directory and always sends STOP before removing its private files.
**
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "util.h"

#define OUTPUT_SIZE 4096

/* Reserve an unused IPv4 loopback port without retaining the descriptor. */
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

/*
**
** Execute one public command with both output streams captured.
**
** The daemon command returns only after its readiness handshake, while
** status, malformed-control, and stop commands produce bounded output.  A
** pipe therefore remains safe here and makes diagnostics available on failure.
**
*/
static int
run_command(char *const argv[], char *output, size_t length)
{
	int	descriptors[2];
	int	status;
	int	result;
	pid_t	child;
	ssize_t count;
	size_t	used;

	if (pipe(descriptors) == -1)
		return -1;
	child = fork();
	if (child == -1) {
		close(descriptors[0]);
		close(descriptors[1]);
		return -1;
	}
	if (child == 0) {
		close(descriptors[0]);
		if (dup2(descriptors[1], STDOUT_FILENO) == -1 ||
		    dup2(descriptors[1], STDERR_FILENO) == -1)
			_exit(126);
		close(descriptors[1]);
		execv("../src/oaioauthc", argv);
		_exit(127);
	}
	close(descriptors[1]);
	used = 0;
	while (used + 1 < length &&
	    (count = read(descriptors[0], output + used, length - used - 1)) >
		0)
		used += (size_t)count;
	output[used] = '\0';
	close(descriptors[0]);
	do {
		result = waitpid(child, &status, 0);
	} while (result == -1 && errno == EINTR);
	if (result != child || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/*
** Execute one command with stdout connected to a pipe that has no reader.
**
** app_main ignores SIGPIPE, so writing the log returns EPIPE to daemon_logs.
** Stderr remains captured separately to prove that the failure initializes a
** complete diagnostic rather than passing untouched stack bytes to fprintf.
*/
static int
run_command_closed_stdout(char *const argv[], char *output, size_t length)
{
	int	closed_output[2];
	int	diagnostics[2];
	int	status;
	int	result;
	pid_t	child;
	ssize_t count;
	size_t	used;

	if (pipe(closed_output) == -1)
		return -1;
	if (pipe(diagnostics) == -1) {
		close(closed_output[0]);
		close(closed_output[1]);
		return -1;
	}
	child = fork();
	if (child == -1) {
		close(closed_output[0]);
		close(closed_output[1]);
		close(diagnostics[0]);
		close(diagnostics[1]);
		return -1;
	}
	if (child == 0) {
		close(closed_output[0]);
		close(diagnostics[0]);
		if (dup2(closed_output[1], STDOUT_FILENO) == -1 ||
		    dup2(diagnostics[1], STDERR_FILENO) == -1)
			_exit(126);
		close(closed_output[1]);
		close(diagnostics[1]);
		execv("../src/oaioauthc", argv);
		_exit(127);
	}
	close(closed_output[0]);
	close(closed_output[1]);
	close(diagnostics[1]);
	used = 0;
	while (used + 1 < length &&
	    (count = read(diagnostics[0], output + used, length - used - 1)) >
		0)
		used += (size_t)count;
	output[used] = '\0';
	close(diagnostics[0]);
	do {
		result = waitpid(child, &status, 0);
	} while (result == -1 && errno == EINTR);
	if (result != child || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/* Wait until a runtime path exists or the bounded startup deadline expires. */
static int
wait_for_path(const char *path, int present)
{
	struct timespec delay;
	int		attempt;
	int		exists;

	delay.tv_sec = 0;
	delay.tv_nsec = 10000000L;
	for (attempt = 0; attempt < 200; attempt++) {
		exists = access(path, F_OK) == 0;
		if (exists == present)
			return 0;
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

/* Send one bounded control line directly to the daemon socket. */
static int
control_request(const char *path, const char *request, char *response,
    size_t length)
{
	struct sockaddr_un address;
	size_t		   used;
	ssize_t		   count;
	int		   fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(address.sun_path)) {
		close(fd);
		return -1;
	}
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    write_all(fd, request, strlen(request)) == -1) {
		close(fd);
		return -1;
	}
	used = 0;
	while (used + 1 < length &&
	    (count = read(fd, response + used, length - used - 1)) > 0)
		used += (size_t)count;
	response[used] = '\0';
	close(fd);
	return count == 0 ? 0 : -1;
}

/* Verify one private runtime file has exactly the expected mode bits. */
static int
check_mode(const char *path, mode_t expected)
{
	struct stat state;

	return stat(path, &state) == 0 && (state.st_mode & 0777) == expected
	    ? 0
	    : -1;
}

/* Extract the daemon PID from a trusted STATUS response for signal testing. */
static int
extract_pid(const char *status, pid_t *pid)
{
	const char *cursor;
	char	   *end;
	long	    value;

	cursor = strstr(status, "\"pid\":");
	if (cursor == NULL)
		return -1;
	cursor += strlen("\"pid\":");
	errno = 0;
	value = strtol(cursor, &end, 10);
	if (errno != 0 || end == cursor || value <= 0 ||
	    (long)(pid_t)value != value)
		return -1;
	*pid = (pid_t)value;
	return 0;
}

/* Exercise startup, status, malformed input, duplicate start, and stop. */
static int
test_daemon_lifecycle(void)
{
	char  control_path[PATH_MAX];
	char  directory[] = "/tmp/oaioauthc-daemon-test-XXXXXX";
	char  output[OUTPUT_SIZE];
	char  port[16];
	char *start_argv[] = { "../src/oaioauthc", "serve", "--daemon",
		"--runtime-dir", directory, "--port", port, "--models",
		"gpt-test", "--codex-version", "9.9.9", NULL };
	char *status_argv[] = { "../src/oaioauthc", "status", "--runtime-dir",
		directory, NULL };
	char *logs_argv[] = { "../src/oaioauthc", "logs", "--runtime-dir",
		directory, NULL };
	char *stop_argv[] = { "../src/oaioauthc", "stop", "--runtime-dir",
		directory, NULL };
	int   result;
	int   started;

	result = -1;
	started = 0;
	memset(control_path, 0, sizeof(control_path));
	if (mkdtemp(directory) == NULL ||
	    reserve_port(port, sizeof(port)) == -1)
		return -1;
	if (snprintf(control_path, sizeof(control_path), "%s/control.sock",
		directory) >= (int)sizeof(control_path))
		goto cleanup;
	result = run_command(start_argv, output, sizeof(output));
	if (result != 0 || strstr(output, "daemon started") == NULL)
		goto cleanup;
	started = 1;
	if (check_mode(directory, 0700) == -1 ||
	    check_mode(control_path, 0600) == -1)
		goto cleanup;
	if (snprintf(output, sizeof(output), "%s/runtime.json", directory) >=
		(int)sizeof(output) ||
	    check_mode(output, 0600) == -1)
		goto cleanup;
	if (run_command(status_argv, output, sizeof(output)) != 0 ||
	    strstr(output, "\"status\":\"running\"") == NULL)
		goto cleanup;
	if (control_request(control_path, "BOGUS\n", output, sizeof(output)) ==
		-1 ||
	    strstr(output, "unknown command") == NULL)
		goto cleanup;
	if (run_command(start_argv, output, sizeof(output)) == 0 ||
	    strstr(output, "already running") == NULL)
		goto cleanup;
	if (run_command(stop_argv, output, sizeof(output)) != 0 ||
	    strstr(output, "stopping") == NULL)
		goto cleanup;
	started = 0;
	if (wait_for_path(control_path, 0) == -1 ||
	    run_command(status_argv, output, sizeof(output)) == 0)
		goto cleanup;
	if (run_command_closed_stdout(logs_argv, output, sizeof(output)) != 1 ||
	    strstr(output, "could not write daemon log output:") == NULL)
		goto cleanup;
	result = 0;

cleanup:
	if (started)
		(void)run_command(stop_argv, output, sizeof(output));
	(void)snprintf(output, sizeof(output), "%s/runtime.json", directory);
	(void)unlink(output);
	(void)unlink(control_path);
	(void)snprintf(output, sizeof(output), "%s/server.log", directory);
	(void)unlink(output);
	(void)snprintf(output, sizeof(output), "%s/runtime.lock", directory);
	(void)unlink(output);
	(void)rmdir(directory);
	return result;
}

/* Confirm an external SIGTERM follows the same cleanup path as STOP. */
static int
test_daemon_signal_cleanup(void)
{
	char  control_path[PATH_MAX];
	char  directory[] = "/tmp/oaioauthc-signal-test-XXXXXX";
	char  output[OUTPUT_SIZE];
	char  port[16];
	char *start_argv[] = { "../src/oaioauthc", "serve", "--daemon",
		"--runtime-dir", directory, "--port", port, "--models",
		"gpt-test", "--codex-version", "9.9.9", NULL };
	char *status_argv[] = { "../src/oaioauthc", "status", "--runtime-dir",
		directory, NULL };
	pid_t pid;
	int   started;
	int   result;

	result = -1;
	started = 0;
	pid = -1;
	memset(control_path, 0, sizeof(control_path));
	if (mkdtemp(directory) == NULL ||
	    reserve_port(port, sizeof(port)) == -1)
		return -1;
	if (snprintf(control_path, sizeof(control_path), "%s/control.sock",
		directory) >= (int)sizeof(control_path))
		goto cleanup;
	if (run_command(start_argv, output, sizeof(output)) != 0)
		goto cleanup;
	started = 1;
	if (run_command(status_argv, output, sizeof(output)) != 0 ||
	    extract_pid(output, &pid) == -1 || kill(pid, SIGTERM) == -1)
		goto cleanup;
	started = 0;
	if (wait_for_path(control_path, 0) == -1 ||
	    access(directory, F_OK) == -1)
		goto cleanup;
	result = 0;

cleanup:
	if (started && pid > 0)
		(void)kill(pid, SIGTERM);
	(void)snprintf(output, sizeof(output), "%s/runtime.json", directory);
	(void)unlink(output);
	(void)unlink(control_path);
	(void)snprintf(output, sizeof(output), "%s/server.log", directory);
	(void)unlink(output);
	(void)snprintf(output, sizeof(output), "%s/runtime.lock", directory);
	(void)unlink(output);
	(void)rmdir(directory);
	return result;
}

int
main(void)
{
	return test_daemon_lifecycle() == -1 ||
		test_daemon_signal_cleanup() == -1
	    ? 1
	    : 0;
}
