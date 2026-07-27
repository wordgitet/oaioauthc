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

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test.h"

/* Run one login child, optionally cancelling it after startup. */
static int
run_login_child(const char *timeout, int cancel_signal, char *output,
    size_t output_length)
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
		    "--login-timeout-ms", timeout, "--oauth-file",
		    "/tmp/oaioauthc-login-test-missing.json", (char *)NULL);
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
	cursor = strstr(output, cancel_signal == 0 ? "timed out" : "cancelled");
	return cursor == NULL ? -1 : 0;
}

/* Verify timeout and SIGTERM cancellation both terminate login cleanly. */
int
main(void)
{
	char output[4096];

	CHECK(run_login_child("100", 0, output, sizeof(output)) == 0);
	CHECK(run_login_child("5000", SIGTERM, output, sizeof(output)) == 0);
	return 0;
}
