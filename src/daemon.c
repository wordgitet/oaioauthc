/*
** Detached daemon lifecycle and local control commands.
**
** A daemon keeps all mutable state below a private runtime directory.  The
** lock is acquired before stale metadata or sockets are removed, so a second
** start cannot destroy a live instance.  The control socket is local-only
** and accepts one bounded, newline-terminated command per connection.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "daemon.h"
#include "util.h"

#define CONTROL_LINE_MAX 4096
#define CONTROL_TIMEOUT	 2
#define STOP_TIMEOUT_MS	 10000
#define LOG_POLL_MS	 100

struct runtime_paths {
	char *directory;
	char *lock;
	char *metadata;
	char *control;
	char *log;
};

struct daemon_state {
	struct runtime_paths	    paths;
	int			    lock_fd;
	int			    control_fd;
	int			    ready_fd;
	pid_t			    pid;
	const struct proxy_options *options;
	int			    ready_sent;
};

/* Format a bounded diagnostic message for a caller-owned error buffer. */
static void
set_error(char *error, size_t length, const char *format, ...)
{
	va_list ap;

	if (error == NULL || length == 0)
		return;
	va_start(ap, format);
	(void)vsnprintf(error, length, format, ap);
	va_end(ap);
}

/* Release every path allocation owned by one runtime-path bundle. */
static void
runtime_paths_free(struct runtime_paths *paths)
{
	free(paths->directory);
	free(paths->lock);
	free(paths->metadata);
	free(paths->control);
	free(paths->log);
	memset(paths, 0, sizeof(*paths));
}

/* Select the documented state-directory fallback without touching the disk. */
static char *
default_runtime_directory(void)
{
	const char *base;
	char	   *directory;
	char	   *state;

	base = getenv("XDG_STATE_HOME");
	if (base != NULL && base[0] != '\0')
		return oaio_join_path(base, "oaioauthc");
	state = oaio_join_path(oaio_home_dir(), ".local/state");
	if (state != NULL) {
		directory = oaio_join_path(state, "oaioauthc");
		free(state);
		if (directory != NULL)
			return directory;
	}
	return oaio_join_path(".", ".local/state/oaioauthc");
}

/* Allocate all fixed runtime filenames below directory. */
static int
runtime_paths_init(struct runtime_paths *paths, const char *directory,
    char *error, size_t length)
{
	memset(paths, 0, sizeof(*paths));
	/*
	** Keep every derived name in one ownership bundle.  Callers can then
	** abort any allocation stage with one cleanup path without reconstructing
	** a partially initialized filename or accidentally unlinking another
	** directory.
	*/
	paths->directory = directory == NULL ? default_runtime_directory()
					     : oaio_strdup(directory);
	if (paths->directory == NULL || paths->directory[0] == '\0') {
		set_error(error, length,
		    "could not allocate daemon runtime directory");
		runtime_paths_free(paths);
		return -1;
	}
	paths->lock = oaio_join_path(paths->directory, "runtime.lock");
	paths->metadata = oaio_join_path(paths->directory, "runtime.json");
	paths->control = oaio_join_path(paths->directory, "control.sock");
	paths->log = oaio_join_path(paths->directory, "server.log");
	if (paths->lock == NULL || paths->metadata == NULL ||
	    paths->control == NULL || paths->log == NULL) {
		set_error(error, length,
		    "could not allocate daemon runtime paths");
		runtime_paths_free(paths);
		return -1;
	}
	if (strlen(paths->control) >=
	    sizeof(((struct sockaddr_un *)0)->sun_path)) {
		set_error(error, length,
		    "daemon control socket path is too long");
		runtime_paths_free(paths);
		return -1;
	}
	return 0;
}

/* Create the private runtime directory and enforce its mode. */
static int
runtime_directory_prepare(const struct runtime_paths *paths, char *error,
    size_t length)
{
	/*
	** make_parent_directories creates missing ancestors with mode 0700.
	** chmod also tightens an existing selected directory before the daemon
	** creates a Unix socket whose pathname would otherwise be discoverable
	** by other users.
	*/
	if (make_parent_directories(paths->lock) == -1 ||
	    (mkdir(paths->directory, 0700) == -1 && errno != EEXIST) ||
	    chmod(paths->directory, 0700) == -1) {
		set_error(error, length,
		    "could not create daemon runtime directory %s: "
		    "%s",
		    paths->directory, strerror(errno));
		return -1;
	}
	return 0;
}

/* Acquire the stable inode lock before cleaning any stale runtime files. */
static int
runtime_lock_open(const struct runtime_paths *paths, char *error, size_t length)
{
	struct flock lock;
	int	     fd;

	fd = open(paths->lock, O_RDWR | O_CREAT, 0600);
	if (fd == -1) {
		set_error(error, length, "could not open daemon lock: %s",
		    strerror(errno));
		return -1;
	}
	(void)fchmod(fd, 0600);
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lock) == -1) {
		if (errno == EACCES || errno == EAGAIN)
			set_error(error, length,
			    "oaioauthc is already running");
		else
			set_error(error, length,
			    "could not lock daemon runtime: %s",
			    strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* Remove stale names only after the caller owns the runtime lock. */
static void
runtime_remove_stale(const struct runtime_paths *paths)
{
	(void)unlink(paths->metadata);
	(void)unlink(paths->control);
}

/* Open and bind the private AF_UNIX control endpoint. */
static int
control_socket_open(const struct runtime_paths *paths, char *error,
    size_t length)
{
	struct sockaddr_un address;
	int		   fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		set_error(error, length,
		    "could not create daemon control socket: %s",
		    strerror(errno));
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
	    paths->control);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    chmod(paths->control, 0600) == -1 || listen(fd, 8) == -1) {
		set_error(error, length,
		    "could not bind daemon control socket: %s",
		    strerror(errno));
		close(fd);
		(void)unlink(paths->control);
		return -1;
	}
	return fd;
}

/* Build private metadata without interpolating unescaped user strings. */
static char *
runtime_metadata(const struct daemon_state *state)
{
	struct buffer api_buffer;
	json_t	     *root;
	char	     *text;
	char	     *api;
	const char   *host;
	const char   *port;

	host = state->options->host == NULL ? "127.0.0.1"
					    : state->options->host;
	port = state->options->port == NULL ? "10531" : state->options->port;
	/*
	** Build the display URL through the shared bounded buffer.  This keeps
	** additions length-checked even when a caller supplies unusually long
	** host or port strings.
	*/
	buffer_init(&api_buffer);
	if (buffer_append_string(&api_buffer, "http://") == -1 ||
	    buffer_append_string(&api_buffer, host) == -1 ||
	    buffer_append_string(&api_buffer, ":") == -1 ||
	    buffer_append_string(&api_buffer, port) == -1 ||
	    buffer_append_string(&api_buffer, "/v1") == -1) {
		buffer_free(&api_buffer);
		return NULL;
	}
	api = buffer_steal(&api_buffer);
	root = json_pack("{s:s,s:I,s:s,s:s,s:I}", "status", "running", "pid",
	    (json_int_t)state->pid, "api", api, "log", state->paths.log,
	    "started", (json_int_t)time(NULL));
	free(api);
	if (root == NULL)
		return NULL;
	text = json_dumps(root, JSON_COMPACT);
	json_decref(root);
	return text;
}

/* Install complete metadata atomically before notifying the starter. */
static int
runtime_metadata_write(const struct daemon_state *state, char *error,
    size_t length)
{
	char *text;
	int   result;

	text = runtime_metadata(state);
	if (text == NULL) {
		set_error(error, length, "could not format daemon metadata");
		return -1;
	}
	result = write_private_file(state->paths.metadata, text);
	if (result == -1)
		set_error(error, length, "could not write daemon metadata: %s",
		    strerror(errno));
	free(text);
	return result;
}

/* Make local control clients fail promptly instead of holding the listener. */
static void
control_timeout(int fd)
{
	struct timeval timeout;

	timeout.tv_sec = CONTROL_TIMEOUT;
	timeout.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	    sizeof(timeout));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
	    sizeof(timeout));
}

/* Read one bounded ASCII command and reject binary, truncated, or oversized input. */
static int
control_read_command(int fd, char *command, size_t length)
{
	unsigned char byte;
	ssize_t	      count;
	size_t	      used;

	used = 0;
	for (;;) {
		count = read(fd, &byte, sizeof(byte));
		if (count == -1 && errno == EINTR)
			continue;
		if (count != 1 || byte == '\0' || byte == '\r')
			return -1;
		if (used + 1 >= length)
			return -1;
		command[used++] = (char)byte;
		if (byte == '\n')
			break;
	}
	command[used] = '\0';
	return 0;
}

/* Send one complete line and report whether the peer accepted the write. */
static int
control_reply(int fd, const char *reply)
{
	return write_all(fd, reply, strlen(reply));
}

/* Respond to STATUS or STOP and return one when the proxy should stop. */
static int
daemon_control(int fd, void *argument)
{
	struct daemon_state *state;
	char		     command[CONTROL_LINE_MAX];
	char		    *metadata;
	int		     result;

	state = argument;
	control_timeout(fd);
	/*
	** Read exactly one newline-terminated command before dispatch.  The
	** callback never parses arbitrary JSON and never accepts a PID supplied
	** by a client, which keeps the administrative surface intentionally small.
	*/
	if (control_read_command(fd, command, sizeof(command)) == -1) {
		(void)control_reply(fd, "{\"error\":\"invalid command\"}\n");
		return 0;
	}
	if (strcmp(command, "STATUS\n") == 0) {
		metadata = runtime_metadata(state);
		result = metadata == NULL ? -1 : control_reply(fd, metadata);
		free(metadata);
		if (result == 0)
			result = control_reply(fd, "\n");
		return 0;
	}
	if (strcmp(command, "STOP\n") == 0) {
		(void)control_reply(fd, "{\"status\":\"stopping\"}\n");
		return 1;
	}
	(void)control_reply(fd, "{\"error\":\"unknown command\"}\n");
	return 0;
}

/* Notify the original process only after the public listener is bound. */
static int
daemon_ready(void *argument)
{
	struct daemon_state *state;

	state = argument;
	if (state->ready_sent)
		return 0;
	if (write_all(state->ready_fd, "R\n", 2) == -1)
		return -1;
	close(state->ready_fd);
	state->ready_fd = -1;
	state->ready_sent = 1;
	return 0;
}

/* Redirect daemon standard streams to the private append-only server log. */
static int
daemon_redirect_stdio(const struct runtime_paths *paths, char *error,
    size_t length)
{
	int fd;
	int null_fd;

	fd = open(paths->log, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd == -1) {
		set_error(error, length, "could not open daemon log: %s",
		    strerror(errno));
		return -1;
	}
	(void)fchmod(fd, 0600);
	null_fd = open("/dev/null", O_RDONLY);
	if (null_fd == -1 || dup2(null_fd, STDIN_FILENO) == -1 ||
	    dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1) {
		set_error(error, length,
		    "could not redirect daemon standard streams: "
		    "%s",
		    strerror(errno));
		if (null_fd != -1)
			close(null_fd);
		close(fd);
		return -1;
	}
	if (null_fd != STDIN_FILENO)
		close(null_fd);
	if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
		close(fd);
	return 0;
}

/* Write one startup result line and close the one-shot readiness channel. */
static void
daemon_startup_result(struct daemon_state *state, int success,
    const char *message)
{
	char line[512];
	int  length;

	if (state->ready_fd == -1)
		return;
	if (success)
		(void)write_all(state->ready_fd, "R\n", 2);
	else {
		length = snprintf(line, sizeof(line), "E %s\n", message);
		if (length > 0 && (size_t)length < sizeof(line))
			(void)write_all(state->ready_fd, line, (size_t)length);
	}
	close(state->ready_fd);
	state->ready_fd = -1;
}

/* Run the detached child after the original process has forked it. */
static void
daemon_child(struct daemon_state *state)
{
	struct proxy_control control;
	char		     error[256];
	int		     result;
	pid_t		     child;

	if (setsid() == -1) {
		daemon_startup_result(state, 0,
		    "could not create daemon session");
		_exit(1);
	}
	/*
	** The first child exists only to create a session and a grandchild.  A
	** failed second fork must be reported through readiness instead of
	** accidentally continuing as an untracked foreground process.
	*/
	child = fork();
	if (child == -1) {
		daemon_startup_result(state, 0, "could not fork daemon worker");
		_exit(1);
	}
	if (child > 0)
		_exit(0);
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
		daemon_startup_result(state, 0, "could not ignore SIGHUP");
		_exit(1);
	}
	(void)umask(077);
	state->pid = getpid();
	state->lock_fd = runtime_lock_open(&state->paths, error, sizeof(error));
	if (state->lock_fd == -1) {
		daemon_startup_result(state, 0, error);
		_exit(1);
	}
	runtime_remove_stale(&state->paths);
	if (daemon_redirect_stdio(&state->paths, error, sizeof(error)) == -1)
		goto fail;
	state->control_fd =
	    control_socket_open(&state->paths, error, sizeof(error));
	if (state->control_fd == -1)
		goto fail;
	if (runtime_metadata_write(state, error, sizeof(error)) == -1)
		goto fail;
	memset(&control, 0, sizeof(control));
	control.fd = state->control_fd;
	control.callback = daemon_control;
	control.argument = state;
	control.ready = daemon_ready;
	result = proxy_serve(state->options, &control, error, sizeof(error));
	if (result == -1 && !state->ready_sent)
		daemon_startup_result(state, 0, error);
	else if (!state->ready_sent)
		daemon_startup_result(state, 1, NULL);
	if (result == -1)
		(void)fprintf(stderr, "%s\n", error);
	(void)unlink(state->paths.metadata);
	(void)unlink(state->paths.control);
	close(state->control_fd);
	close(state->lock_fd);
	runtime_paths_free(&state->paths);
	_exit(result == -1 ? 1 : 0);

fail:
	if (state->control_fd != -1) {
		close(state->control_fd);
		(void)unlink(state->paths.control);
	}
	(void)unlink(state->paths.metadata);
	if (state->lock_fd != -1)
		close(state->lock_fd);
	daemon_startup_result(state, 0, error);
	runtime_paths_free(&state->paths);
	_exit(1);
}

/* Start a detached daemon and wait for a bound-listener readiness result. */
int
daemon_serve(const struct proxy_options *options, const char *directory,
    char *error, size_t length)
{
	struct daemon_state state;
	char		    response[512];
	char		   *cursor;
	char		   *newline;
	pid_t		    child;
	ssize_t		    count;
	int		    descriptors[2];
	int		    status;
	int		    result;

	memset(&state, 0, sizeof(state));
	state.lock_fd = -1;
	state.control_fd = -1;
	state.ready_fd = -1;
	state.options = options;
	/*
	** The readiness pipe is deliberately held across both forks.  The
	** original caller therefore waits for a definitive R/E line from the
	** grandchild instead of treating an intermediate fork as successful
	** startup while bind or listen may still fail.
	*/
	if (runtime_paths_init(&state.paths, directory, error, length) == -1 ||
	    runtime_directory_prepare(&state.paths, error, length) == -1)
		goto fail;
	if (pipe(descriptors) == -1) {
		set_error(error, length,
		    "could not create daemon readiness pipe: %s",
		    strerror(errno));
		goto fail;
	}
	child = fork();
	if (child == -1) {
		close(descriptors[0]);
		close(descriptors[1]);
		set_error(error, length, "could not fork daemon: %s",
		    strerror(errno));
		goto fail;
	}
	if (child == 0) {
		close(descriptors[0]);
		state.ready_fd = descriptors[1];
		daemon_child(&state);
		_exit(1);
	}
	close(descriptors[1]);
	result = 0;
	memset(response, 0, sizeof(response));
	cursor = response;
	for (;;) {
		if ((size_t)(cursor - response) + 1 >= sizeof(response))
			break;
		count = read(descriptors[0], cursor,
		    sizeof(response) - (size_t)(cursor - response) - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			break;
		cursor += count;
	}
	*cursor = '\0';
	close(descriptors[0]);
	(void)waitpid(child, &status, 0);
	if (response[0] != 'R') {
		newline = strchr(response, '\n');
		if (newline != NULL)
			*newline = '\0';
		set_error(error, length, "%s",
		    response[0] == 'E' && response[1] == ' '
			? response + 2
			: "daemon failed to start");
		result = -1;
	} else {
		(void)fprintf(stdout, "oaioauthc daemon started in %s\n",
		    state.paths.directory);
	}
	runtime_paths_free(&state.paths);
	return result;

fail:
	runtime_paths_free(&state.paths);
	return -1;
}

/* Connect one control client and return its descriptor or a diagnostic. */
static int
control_connect(const struct runtime_paths *paths, char *error, size_t length)
{
	struct sockaddr_un address;
	int		   fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		goto fail;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
	    paths->control);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
		close(fd);
		goto fail;
	}
	control_timeout(fd);
	return fd;

fail:
	set_error(error, length, "oaioauthc is not running");
	return -1;
}

/* Read one complete bounded control response into a NUL-terminated buffer. */
static int
control_read_response(int fd, struct buffer *response)
{
	char	chunk[1024];
	ssize_t count;

	while ((count = read(fd, chunk, sizeof(chunk))) > 0) {
		if (response->len > CONTROL_LINE_MAX ||
		    (size_t)count > CONTROL_LINE_MAX - response->len ||
		    buffer_append(response, chunk, (size_t)count) == -1)
			return -1;
	}
	return count == 0 ? 0 : -1;
}

/* Resolve paths, send one command, and print the daemon's bounded response. */
static int
daemon_command(const char *directory, const char *command, FILE *stream,
    char *error, size_t length)
{
	struct buffer	     response;
	struct runtime_paths paths;
	int		     fd;
	int		     result;

	if (runtime_paths_init(&paths, directory, error, length) == -1)
		return -1;
	fd = control_connect(&paths, error, length);
	if (fd == -1) {
		runtime_paths_free(&paths);
		return -1;
	}
	result = write_all(fd, command, strlen(command));
	buffer_init(&response);
	if (result == 0)
		result = control_read_response(fd, &response);
	close(fd);
	if (result == 0 && response.len > 0)
		result = fwrite(response.data, 1, response.len, stream) ==
			response.len
		    ? 0
		    : -1;
	if (result == -1)
		set_error(error, length, "daemon control request failed: %s",
		    strerror(errno));
	buffer_free(&response);
	runtime_paths_free(&paths);
	return result;
}

/* Query the live daemon through its control socket. */
int
daemon_status(const char *directory, FILE *stream, char *error, size_t length)
{
	return daemon_command(directory, "STATUS\n", stream, error, length);
}

/* Request graceful shutdown and wait for the control socket to disappear. */
int
daemon_stop(const char *directory, FILE *stream, char *error, size_t length)
{
	struct runtime_paths paths;
	struct timespec	     delay;
	int		     result;
	int		     elapsed;

	if (runtime_paths_init(&paths, directory, error, length) == -1)
		return -1;
	/*
	** Stop is a request/confirmation operation: daemon_command waits for the
	** daemon's reply, and the loop below waits for pathname removal before
	** returning success.  A response alone is not proof that workers finished.
	*/
	result = daemon_command(directory, "STOP\n", stream, error, length);
	if (result == -1) {
		runtime_paths_free(&paths);
		return -1;
	}
	delay.tv_sec = 0;
	delay.tv_nsec = 100000000L;
	for (elapsed = 0; elapsed < STOP_TIMEOUT_MS; elapsed += 100) {
		if (access(paths.control, F_OK) == -1 && errno == ENOENT)
			break;
		(void)nanosleep(&delay, NULL);
	}
	if (elapsed >= STOP_TIMEOUT_MS) {
		set_error(error, length,
		    "daemon did not stop within %d seconds",
		    STOP_TIMEOUT_MS / 1000);
		result = -1;
	}
	runtime_paths_free(&paths);
	return result;
}

/* Return whether a daemon still answers its private control socket. */
static int
daemon_is_running(const struct runtime_paths *paths)
{
	char error[64];
	int  fd;

	fd = control_connect(paths, error, sizeof(error));
	if (fd == -1)
		return 0;
	(void)write_all(fd, "STATUS\n", 7);
	close(fd);
	return 1;
}

/* Stream the regular log, optionally following until the daemon exits. */
int
daemon_logs(const char *directory, int follow, FILE *stream, char *error,
    size_t length)
{
	struct runtime_paths paths;
	struct timespec	     delay;
	char		     chunk[4096];
	ssize_t		     count;
	int		     fd;
	int		     result;
	int		     saved_errno;

	if (runtime_paths_init(&paths, directory, error, length) == -1)
		return -1;
	fd = open(paths.log, O_RDONLY);
	if (fd == -1) {
		set_error(error, length, "could not open daemon log: %s",
		    strerror(errno));
		runtime_paths_free(&paths);
		return -1;
	}
	delay.tv_sec = 0;
	delay.tv_nsec = LOG_POLL_MS * 1000000L;
	result = 0;
	/*
	** Regular-file reads naturally stop at EOF.  Follow mode polls in short
	** intervals so appended output becomes visible without loading the whole
	** log or blocking forever after the daemon has removed its socket.
	*/
	for (;;) {
		count = read(fd, chunk, sizeof(chunk));
		if (count > 0) {
			if (fwrite(chunk, 1, (size_t)count, stream) !=
				(size_t)count ||
			    fflush(stream) == EOF) {
				saved_errno = errno == 0 ? EIO : errno;
				set_error(error, length,
				    "could not write daemon log output: %s",
				    strerror(saved_errno));
				result = -1;
				break;
			}
			continue;
		}
		if (count == -1 && errno == EINTR)
			continue;
		if (count == -1) {
			set_error(error, length,
			    "could not read daemon log: %s", strerror(errno));
			result = -1;
			break;
		}
		if (!follow || !daemon_is_running(&paths))
			break;
		(void)nanosleep(&delay, NULL);
	}
	close(fd);
	runtime_paths_free(&paths);
	return result;
}
