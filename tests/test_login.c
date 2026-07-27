/*
 * Process-level tests for the loopback OAuth login command.
 *
 * The login command is intentionally tested through the public executable,
 * not by reaching into app.c's static listener helpers.  This verifies that
 * option parsing, PKCE setup, signal installation, descriptor cleanup, and
 * the bounded callback wait work together.  No browser, credential file, or
 * upstream OAuth request is needed: both cases finish before a callback code
 * can be exchanged.
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test.h"

/* Run one login child, optionally cancelling it after startup. */
static int
run_login_child(const char *timeout, int cancel_signal, const char *auth_path,
    const char *expected, char *output, size_t output_length)
{
	struct timespec delay;
	char	       *cursor;
	int		output_pipe[2];
	int		status;
	int		attempt;
	pid_t		pid;
	ssize_t		count;
	size_t		used;

	if (pipe(output_pipe) == -1)
		return -1;
	pid = fork();
	if (pid == -1) {
		close(output_pipe[0]);
		close(output_pipe[1]);
		return -1;
	}
	if (pid == 0) {
		close(output_pipe[0]);
		if (dup2(output_pipe[1], STDERR_FILENO) == -1)
			_exit(126);
		close(output_pipe[1]);
		execl("../src/oaioauthc", "oaioauthc", "login", "--no-open",
		    "--login-timeout-ms", timeout, "--oauth-file", auth_path,
		    (char *)NULL);
		_exit(127);
	}
	close(output_pipe[1]);
	if (cancel_signal != 0) {
		delay.tv_sec = 0;
		delay.tv_nsec = 100000000;
		(void)nanosleep(&delay, NULL);
		(void)kill(pid, cancel_signal);
	}
	delay.tv_sec = 0;
	delay.tv_nsec = 10000000;
	status = 0;
	for (attempt = 0; attempt < 200; attempt++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		(void)nanosleep(&delay, NULL);
	}
	if (attempt == 200) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, &status, 0);
		close(output_pipe[0]);
		return -1;
	}
	used = 0;
	while (used + 1 < output_length &&
	    (count = read(output_pipe[0], output + used,
		 output_length - used - 1)) > 0)
		used += (size_t)count;
	close(output_pipe[0]);
	output[used] = '\0';
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 1)
		return -1;
	cursor = strstr(output, expected);
	return cursor == NULL ? -1 : 0;
}

/* Verify timeout and SIGTERM cancellation both terminate login cleanly. */
int
main(void)
{
	char auth_path[128];
	char existing_path[128];
	char output[4096];
	int  fd;

	(void)snprintf(auth_path, sizeof(auth_path),
	    "/tmp/oaioauthc-login-test-missing-%ld.json", (long)getpid());
	(void)snprintf(existing_path, sizeof(existing_path),
	    "/tmp/oaioauthc-login-test-existing-%ld.json", (long)getpid());
	(void)unlink(auth_path);
	(void)unlink(existing_path);

	CHECK(run_login_child("100", 0, auth_path, "timed out", output,
		  sizeof(output)) == 0);
	CHECK(run_login_child("5000", SIGTERM, auth_path, "cancelled", output,
		  sizeof(output)) == 0);
	fd = open(existing_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd != -1);
	CHECK(close(fd) == 0);
	CHECK(run_login_child("5000", 0, existing_path, "interactive terminal",
		  output, sizeof(output)) == 0);
	CHECK(unlink(existing_path) == 0);
	return 0;
}
