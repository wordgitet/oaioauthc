/*
** Command-line entry points and the interactive OAuth login callback.
**
** This file owns the user-facing "serve" and "login" commands.  The serve
** command only parses configuration and delegates all request handling to
** proxy.c.  The login command performs the browser-facing half of OAuth:
** it builds a PKCE authorization request, opens a loopback listener, checks
** the returned state, exchanges the code, and stores the resulting Codex
** auth.json session.
**
** The callback listener is restricted to the IPv4 and IPv6 loopback addresses
** on port 1455 and accepts exactly one request.  Its parser recognizes only
** the request line and query parameters needed for the OAuth redirect. Public
** HTTP parsing, request limits, and route dispatch belong to proxy.c instead.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "app.h"
#include "auth.h"
#include "config.h"
#include "daemon.h"
#include "proxy.h"
#include "util.h"

#define CALLBACK_PORT	   1455
#define CALLBACK_LISTENERS 2
#define CALLBACK_URI	   "http://localhost:1455/auth/callback"

/* Set by the short-lived login signal handlers; read by the main thread. */
static volatile sig_atomic_t login_signal_received;

/* Print the complete public command grammar to a diagnostic stream. */
static void
usage(FILE *stream)
{
	(void)fprintf(stream,
	    "Usage:\n"
	    "  oaioauthc serve [-p PORT] [--host HOST] [--models IDS]\n"
	    "                  [--codex-version VERSION] [--base-url URL]\n"
	    "                  [--oauth-file PATH]\n"
	    "                  [--oauth-client-id ID] [--oauth-token-url URL]\n"
	    "                  [--daemon] [--runtime-dir DIR]\n"
	    "                  [--debug-json[=compact|pretty]]\n"
	    "  oaioauthc login [--oauth-file PATH] [--open|--no-open]\n"
	    "                  [--oauth-client-id ID] [--oauth-token-url URL]\n"
	    "                  [--login-timeout-ms MS]\n"
	    "  oaioauthc status [--runtime-dir DIR]\n"
	    "  oaioauthc stop [--runtime-dir DIR]\n"
	    "  oaioauthc logs [--follow] [--runtime-dir DIR]\n"
	    "  oaioauthc --help\n"
	    "  oaioauthc --version\n");
}

/* Parse one positive decimal command-line value within maximum. */
static int
parse_positive_number(const char *value, unsigned long maximum,
    unsigned long *number)
{
	const unsigned char *cursor;
	unsigned long	     digit;
	unsigned long	     result;

	if (value == NULL || value[0] == '\0')
		return -1;
	result = 0;
	for (cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
		if (*cursor < '0' || *cursor > '9')
			return -1;
		digit = (unsigned long)(*cursor - '0');
		if (result > (maximum - digit) / 10)
			return -1;
		result = result * 10 + digit;
	}
	if (result == 0)
		return -1;
	*number = result;
	return 0;
}

/*
** Consume the next argv element for an option that requires a value.
**
** Advancing index to argc on failure makes the command parser stop without
** accidentally treating a missing value as a later independent option.
*/
static const char *
option_value(int *index, int argc, char **argv, const char *name)
{
	if (*index + 1 >= argc) {
		(void)fprintf(stderr, "%s requires a value\n", name);
		*index = argc;
		return NULL;
	}
	(*index)++;
	return argv[*index];
}

/*
** Ask the selected desktop opener to visit url without making login depend on it.
**
** The child is intentionally not waited for: browsers often remain attached
** to the opener, and the loopback callback is the actual completion signal.
** BROWSER is accepted only as a single executable name or path.  It is passed
** directly to execlp rather than to a shell, so environment text cannot become
** command syntax.
*/
static int
open_browser(const char *url)
{
	const char *browser;
	pid_t	    pid;

	browser = getenv("BROWSER");
	if (browser == NULL || browser[0] == '\0' ||
	    strpbrk(browser, " \t\r\n") != NULL) {
#ifdef HAVE_MACOS_OPEN
		browser = "open";
#else
		browser = "xdg-open";
#endif
	}
	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		execlp(browser, browser, url, (char *)NULL);
		_exit(127);
	}
	return 0;
}

/*
** Refuse to overwrite credentials silently.
**
** A login exchange returns bearer credentials, so replacing an existing
** auth.json is a destructive security operation even though auth_save uses an
** atomic rename.  Non-interactive callers cannot answer safely and must opt
** into the replacement from a terminal.
*/
static int
confirm_auth_overwrite(const char *path, int *replace)
{
	char answer[32];

	*replace = 0;
	if (access(path, F_OK) == -1) {
		if (errno == ENOENT)
			return 0;
		(void)fprintf(stderr, "could not inspect auth file %s: %s\n",
		    path, strerror(errno));
		return -1;
	}
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		(void)fprintf(stderr,
		    "OpenAI OAuth credentials already exist at %s.\n"
		    "Run login in an interactive terminal to confirm overwrite.\n",
		    path);
		return -1;
	}
	(void)fprintf(stdout,
	    "OpenAI OAuth credentials already exist at %s.\n"
	    "Sign in with ChatGPT again and overwrite them? [y/N] ",
	    path);
	if (fflush(stdout) == EOF ||
	    fgets(answer, sizeof(answer), stdin) == NULL) {
		(void)fprintf(stderr,
		    "could not read overwrite confirmation\n");
		return -1;
	}
	if (answer[0] != 'y' && answer[0] != 'Y') {
		(void)fprintf(stdout, "Login cancelled.\n");
		return 1;
	}
	*replace = 1;
	return 0;
}

/* Record interruption without calling non-async-signal-safe functions. */
static void
login_signal_handler(int signal_number)
{
	login_signal_received = signal_number;
}

/* Let synchronous helpers observe cancellation without accessing globals. */
static int
login_cancel_requested(void *argument)
{
	(void)argument;
	return login_signal_received != 0;
}

/*
** Return the milliseconds left in a timeout measured from monotonic start.
**
** The timeout is bounded by INT_MAX, so checking whole seconds before the
** multiplication keeps elapsed arithmetic within signed long long.
*/
static int
remaining_timeout_ms(const struct timespec *start, int timeout_ms)
{
	struct timespec now;
	long long	elapsed;
	time_t		seconds;
	long		nanoseconds;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return -1;
	seconds = now.tv_sec - start->tv_sec;
	nanoseconds = now.tv_nsec - start->tv_nsec;
	if (nanoseconds < 0) {
		seconds--;
		nanoseconds += 1000000000L;
	}
	if (seconds < 0)
		return timeout_ms;
	if (seconds > (time_t)(timeout_ms / 1000 + 1))
		return 0;
	elapsed = (long long)seconds * 1000 + nanoseconds / 1000000L;
	if (elapsed >= timeout_ms)
		return 0;
	return timeout_ms - (int)elapsed;
}

/* Install the cancellation handlers used only during one login attempt. */
static int
install_login_signals(struct sigaction *old_interrupt,
    struct sigaction		       *old_terminate)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = login_signal_handler;
	login_signal_received = 0;
	if (sigaction(SIGINT, &action, old_interrupt) == -1)
		return -1;
	if (sigaction(SIGTERM, &action, old_terminate) == -1) {
		(void)sigaction(SIGINT, old_interrupt, NULL);
		return -1;
	}
	return 0;
}

/* Restore process signal behavior after the login callback is closed. */
static void
restore_login_signals(const struct sigaction *old_interrupt,
    const struct sigaction		     *old_terminate)
{
	(void)sigaction(SIGINT, old_interrupt, NULL);
	(void)sigaction(SIGTERM, old_terminate, NULL);
}

/*
** Open loopback listeners used by the OAuth redirect URI.
**
** The redirect uses the hostname "localhost", whose address-family choice is
** controlled by the browser and resolver.  Bind both IPv6 and IPv4 loopback
** addresses so a successful authorization cannot fail solely because one
** family was preferred.  A listener is never exposed on a non-loopback
** interface.
*/
static int
listen_callback(int listeners[CALLBACK_LISTENERS])
{
	struct sockaddr_in  address4;
	struct sockaddr_in6 address6;
	int		    count;
	int		    fd;
	int		    one;
	int		    saved_errno;

	listeners[0] = -1;
	listeners[1] = -1;
	count = 0;
	saved_errno = EAFNOSUPPORT;
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd != -1) {
		one = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
		    sizeof(one));
#ifdef IPV6_V6ONLY
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
		    sizeof(one));
#endif
		memset(&address6, 0, sizeof(address6));
		address6.sin6_family = AF_INET6;
		address6.sin6_addr = in6addr_loopback;
		address6.sin6_port = htons(CALLBACK_PORT);
		if (bind(fd, (struct sockaddr *)&address6, sizeof(address6)) ==
			-1 ||
		    listen(fd, 1) == -1) {
			saved_errno = errno;
			close(fd);
			if (saved_errno != EAFNOSUPPORT &&
			    saved_errno != EPROTONOSUPPORT &&
			    saved_errno != EADDRNOTAVAIL)
				goto fail;
		} else {
			listeners[count++] = fd;
		}
	} else {
		saved_errno = errno;
		if (saved_errno != EAFNOSUPPORT &&
		    saved_errno != EPROTONOSUPPORT)
			goto fail;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		saved_errno = errno;
		goto fail;
	}
	one = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&address4, 0, sizeof(address4));
	address4.sin_family = AF_INET;
	address4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address4.sin_port = htons(CALLBACK_PORT);
	if (bind(fd, (struct sockaddr *)&address4, sizeof(address4)) == -1 ||
	    listen(fd, 1) == -1) {
		saved_errno = errno;
		close(fd);
		goto fail;
	}
	listeners[count++] = fd;
	return count;

fail:
	while (count > 0)
		close(listeners[--count]);
	errno = saved_errno;
	return -1;
}

/* Close every callback listener while retaining the caller's errno. */
static void
close_callback_listeners(int listeners[CALLBACK_LISTENERS])
{
	int index;
	int saved_errno;

	saved_errno = errno;
	for (index = 0; index < CALLBACK_LISTENERS; index++) {
		if (listeners[index] != -1) {
			close(listeners[index]);
			listeners[index] = -1;
		}
	}
	errno = saved_errno;
}

/* Return one hexadecimal digit's numeric value, or -1 for invalid input. */
static int
hex_value(char character)
{
	if (character >= '0' && character <= '9')
		return (char)(character - '0');
	if (character >= 'a' && character <= 'f')
		return (char)(character - 'a' + 10);
	if (character >= 'A' && character <= 'F')
		return (char)(character - 'A' + 10);
	return -1;
}

/*
** Return a decoded query parameter value owned by the caller.
**
** The search is exact on the parameter name.  Percent escapes and '+' follow
** form-query rules, while malformed escapes and decoded NUL bytes are rejected
** so callers never compare truncated security-sensitive values such as state.
*/
static char *
query_value(const char *target, const char *name)
{
	const char   *cursor;
	const char   *end;
	const char   *equal;
	const char   *query;
	struct buffer value;
	char	      decoded;
	int	      high;
	int	      low;

	/* Decode only the selected parameter; reject embedded NULs in the URL. */
	query = strchr(target, '?');
	if (query == NULL)
		return NULL;
	end = NULL;
	equal = NULL;
	cursor = query + 1;
	while (*cursor != '\0') {
		end = strchr(cursor, '&');
		if (end == NULL)
			end = cursor + strlen(cursor);
		equal = memchr(cursor, '=', (size_t)(end - cursor));
		if (equal != NULL && (size_t)(equal - cursor) == strlen(name) &&
		    strncmp(cursor, name, strlen(name)) == 0)
			break;
		if (*end == '\0')
			return NULL;
		cursor = end + 1;
	}
	if (*cursor == '\0' || equal == NULL)
		return NULL;
	cursor = equal + 1;
	buffer_init(&value);
	while (cursor < end) {
		if (*cursor == '%') {
			if (end - cursor < 3)
				goto fail;
			high = hex_value(cursor[1]);
			low = hex_value(cursor[2]);
			if (high < 0 || low < 0)
				goto fail;
			decoded = (char)(high * 16 + low);
			cursor += 3;
		} else {
			decoded = *cursor == '+' ? ' ' : *cursor;
			cursor++;
		}
		if (decoded == '\0' ||
		    buffer_append(&value, &decoded, sizeof(decoded)) == -1)
			goto fail;
	}
	return buffer_steal(&value);

fail:
	buffer_free(&value);
	return NULL;
}

/* Emit the small browser-facing success or callback-validation response. */
static int
send_callback_response(int fd, int status, const char *content_type,
    const char *body)
{
	char header[256];
	int  length;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
	    "Connection: close\r\n\r\n",
	    status, status == 200 ? "OK" : "Bad Request", content_type,
	    strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header))
		return -1;
	if (write_all(fd, header, (size_t)length) == -1)
		return -1;
	return write_all(fd, body, strlen(body));
}

/*
** Perform the complete interactive PKCE login transaction.
**
** The authorization URL and verifier remain in oauth until after the local
** callback passes state validation.  The listener closes after one connection
** so it cannot become a general HTTP service.  Only a successfully exchanged
** and saved session survives this function; all other paths release secrets.
*/
static int
run_login(const struct proxy_options *options, int should_open, int timeout_ms)
{
	struct sigaction     old_interrupt;
	struct sigaction     old_terminate;
	struct pollfd	     descriptors[CALLBACK_LISTENERS];
	struct timespec	     callback_started;
	struct timespec	     request_started;
	struct timeval	     receive_timeout;
	struct oauth_request oauth;
	struct auth_session  session;
	int		     client_fd;
	int		     listener_count;
	int		     listeners[CALLBACK_LISTENERS];
	int		     listener_index;
	int		     poll_result;
	int		     remaining_ms;
	int		     replace_auth;
	int		     signals_installed;
	char		     request[8192];
	ssize_t		     count;
	size_t		     used;
	char		    *code;
	char		    *method;
	char		    *state;
	char		    *target;
	char		    *version;
	char		     error[256];
	const char	    *path;
	const char	    *body;
	int		     overwrite;
	int		     result;

	/*
	 * The state comparison binds the one local redirect to this PKCE request.
	 * Do it before exchanging the code, since the callback listener is not an
	 * authenticated HTTP endpoint.
	 */
	memset(&oauth, 0, sizeof(oauth));
	memset(&session, 0, sizeof(session));
	client_fd = -1;
	listeners[0] = -1;
	listeners[1] = -1;
	code = NULL;
	state = NULL;
	signals_installed = 0;
	result = 1;
	path = options->auth_file == NULL ? auth_default_file()
					  : options->auth_file;
	if (path == NULL) {
		(void)fprintf(stderr, "could not determine auth file path\n");
		return 1;
	}
	overwrite = confirm_auth_overwrite(path, &replace_auth);
	if (overwrite != 0)
		return overwrite < 0 ? 1 : 0;
	listener_count = listen_callback(listeners);
	if (listener_count == -1) {
		if (errno == EADDRINUSE)
			(void)fprintf(stderr,
			    "OAuth callback port %d is already in use\n",
			    CALLBACK_PORT);
		else
			(void)fprintf(stderr,
			    "login needs http://localhost:%d/auth/callback: %s\n",
			    CALLBACK_PORT, strerror(errno));
		return 1;
	}
	if (oauth_request_create(CALLBACK_URI, options->client_id, &oauth,
		error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		goto done;
	}
	if (install_login_signals(&old_interrupt, &old_terminate) == -1) {
		(void)fprintf(stderr,
		    "could not install login signal handlers: %s\n",
		    strerror(errno));
		goto done;
	}
	signals_installed = 1;
	(void)fprintf(stderr, "OpenAI OAuth login URL: %s\n",
	    oauth.authorization_url);
	if (should_open)
		(void)open_browser(oauth.authorization_url);
	for (listener_index = 0; listener_index < listener_count;
	    listener_index++) {
		descriptors[listener_index].fd = listeners[listener_index];
		descriptors[listener_index].events = POLLIN;
		descriptors[listener_index].revents = 0;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &callback_started) == -1) {
		(void)fprintf(stderr,
		    "could not start OAuth callback timeout: %s\n",
		    strerror(errno));
		goto done;
	}
	for (;;) {
		if (login_signal_received != 0) {
			(void)fprintf(stderr, "OAuth login cancelled\n");
			goto done;
		}
		remaining_ms =
		    remaining_timeout_ms(&callback_started, timeout_ms);
		if (remaining_ms == -1) {
			(void)fprintf(stderr,
			    "could not update OAuth callback timeout: %s\n",
			    strerror(errno));
			goto done;
		}
		if (remaining_ms == 0) {
			(void)fprintf(stderr,
			    "OAuth login timed out waiting for callback\n");
			goto done;
		}
		poll_result =
		    poll(descriptors, (nfds_t)listener_count, remaining_ms);
		if (poll_result == -1 && errno == EINTR) {
			continue;
		}
		if (poll_result == 0) {
			(void)fprintf(stderr,
			    "OAuth login timed out waiting for callback\n");
			goto done;
		}
		if (poll_result == -1) {
			(void)fprintf(stderr,
			    "could not wait for OAuth callback: %s\n",
			    strerror(errno));
			goto done;
		}
		for (listener_index = 0; listener_index < listener_count;
		    listener_index++) {
			if ((descriptors[listener_index].revents &
				(POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
				break;
		}
		if (listener_index < listener_count)
			break;
	}
	if (login_signal_received != 0) {
		(void)fprintf(stderr, "OAuth login cancelled\n");
		result = 1;
		goto done;
	}
	if ((descriptors[listener_index].revents & POLLNVAL) != 0) {
		(void)fprintf(stderr,
		    "OAuth callback listener became invalid\n");
		goto done;
	}
	client_fd = accept(listeners[listener_index], NULL, NULL);
	close_callback_listeners(listeners);
	if (client_fd == -1) {
		if (login_signal_received != 0)
			(void)fprintf(stderr, "OAuth login cancelled\n");
		else
			(void)fprintf(stderr,
			    "could not accept OAuth callback: %s\n",
			    strerror(errno));
		goto done;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &request_started) == -1) {
		(void)fprintf(stderr,
		    "could not start OAuth callback request timeout: %s\n",
		    strerror(errno));
		goto done;
	}
	used = 0;
	while (used + 1 < sizeof(request)) {
		if (login_signal_received != 0)
			break;
		remaining_ms =
		    remaining_timeout_ms(&request_started, timeout_ms);
		if (remaining_ms == -1) {
			(void)fprintf(stderr,
			    "could not update OAuth callback request timeout: %s\n",
			    strerror(errno));
			goto done;
		}
		if (remaining_ms == 0) {
			(void)fprintf(stderr,
			    "OAuth login timed out reading callback request\n");
			goto done;
		}
		receive_timeout.tv_sec = remaining_ms / 1000;
		receive_timeout.tv_usec = (remaining_ms % 1000) * 1000;
		if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
			&receive_timeout, sizeof(receive_timeout)) == -1) {
			(void)fprintf(stderr,
			    "could not limit OAuth callback request: %s\n",
			    strerror(errno));
			goto done;
		}
		count =
		    read(client_fd, request + used, sizeof(request) - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			(void)fprintf(stderr,
			    "OAuth login timed out reading callback request\n");
			goto done;
		}
		if (count <= 0)
			break;
		used += (size_t)count;
		request[used] = '\0';
		if (strstr(request, "\r\n\r\n") != NULL)
			break;
	}
	request[used] = '\0';
	if (login_signal_received != 0) {
		(void)fprintf(stderr, "OAuth login cancelled\n");
		goto done;
	}
	method = strtok(request, " ");
	target = strtok(NULL, " ");
	version = strtok(NULL, "\r\n");
	code = target == NULL ? NULL : query_value(target, "code");
	state = target == NULL ? NULL : query_value(target, "state");
	if (method == NULL || strcmp(method, "GET") != 0 || target == NULL ||
	    strncmp(target, "/auth/callback", strlen("/auth/callback")) != 0 ||
	    (target[strlen("/auth/callback")] != '?' &&
		target[strlen("/auth/callback")] != '\0') ||
	    version == NULL ||
	    strncmp(version, "HTTP/1.", strlen("HTTP/1.")) != 0) {
		free(code);
		free(state);
		code = NULL;
		state = NULL;
	}
	if (code == NULL || state == NULL || strcmp(state, oauth.state) != 0) {
		body = "Invalid OAuth callback";
		(void)send_callback_response(client_fd, 400,
		    "text/plain; charset=utf-8", body);
		free(code);
		code = NULL;
		free(state);
		state = NULL;
		goto done;
	}
	body =
	    "<html><body>Sign-in complete. Return to your terminal.</body></html>";
	(void)send_callback_response(client_fd, 200, "text/html; charset=utf-8",
	    body);
	close(client_fd);
	client_fd = -1;
	if (login_signal_received != 0) {
		(void)fprintf(stderr, "OAuth login cancelled\n");
		goto done;
	}
	result = oauth_exchange_code(code, oauth.code_verifier, CALLBACK_URI,
	    options->client_id, options->token_url, login_cancel_requested,
	    NULL, &session, error, sizeof(error));
	free(code);
	code = NULL;
	free(state);
	state = NULL;
	oauth_request_free(&oauth);
	if (result == -1) {
		if (login_signal_received != 0)
			(void)fprintf(stderr, "OAuth login cancelled\n");
		else
			(void)fprintf(stderr, "%s\n", error);
		auth_session_free(&session);
		result = 1;
		goto done;
	}
	if (login_signal_received != 0) {
		(void)fprintf(stderr, "OAuth login cancelled\n");
		result = 1;
		goto done;
	}
	if ((replace_auth ? auth_save(path, &session, error, sizeof(error))
			  : auth_save_new(path, &session, error,
				sizeof(error))) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		auth_session_free(&session);
		result = 1;
		goto done;
	}
	auth_session_free(&session);
	(void)fprintf(stderr, "Credentials saved to %s\n", path);
	result = 0;

done:
	free(code);
	free(state);
	if (client_fd != -1)
		close(client_fd);
	close_callback_listeners(listeners);
	oauth_request_free(&oauth);
	auth_session_free(&session);
	if (signals_installed)
		restore_login_signals(&old_interrupt, &old_terminate);
	return result;
}

/*
** Parse the command line, install process-wide SIGPIPE behavior, and select
** login or serve.  options only borrows argv strings, so it stays valid for
** the synchronous proxy_serve call without a second allocation layer.
*/
int
app_main(int argc, char **argv)
{
	struct proxy_options options;
	const char	    *command;
	const char	    *runtime_directory;
	int		     index;
	int		     open;
	int		     daemon_mode;
	int		     follow_logs;
	char		     error[256];
	const char	    *login_timeout_value;
	unsigned long	     login_timeout;
	unsigned long	     port_number;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		(void)fprintf(stderr, "could not ignore SIGPIPE: %s\n",
		    strerror(errno));
		return 1;
	}
	memset(&options, 0, sizeof(options));
	command = argc > 1 && argv[1][0] != '-' ? argv[1] : "serve";
	index = strcmp(command, "serve") == 0 && argc > 1 && argv[1][0] == '-'
	    ? 1
	    : 2;
	open = 1;
	daemon_mode = 0;
	follow_logs = 0;
	runtime_directory = NULL;
	login_timeout = 300000UL;
	login_timeout_value = NULL;
	for (; index < argc; index++) {
		if (strcmp(argv[index], "--host") == 0)
			options.host =
			    option_value(&index, argc, argv, "--host");
		else if (strcmp(argv[index], "--port") == 0 ||
		    strcmp(argv[index], "-p") == 0)
			options.port =
			    option_value(&index, argc, argv, "--port");
		else if (strncmp(argv[index], "--port=", 7) == 0)
			options.port = argv[index] + 7;
		else if (strcmp(argv[index], "--models") == 0)
			options.models =
			    option_value(&index, argc, argv, "--models");
		else if (strcmp(argv[index], "--codex-version") == 0)
			options.codex_version =
			    option_value(&index, argc, argv, "--codex-version");
		else if (strcmp(argv[index], "--base-url") == 0)
			options.base_url =
			    option_value(&index, argc, argv, "--base-url");
		else if (strcmp(argv[index], "--oauth-file") == 0)
			options.auth_file =
			    option_value(&index, argc, argv, "--oauth-file");
		else if (strcmp(argv[index], "--oauth-client-id") == 0)
			options.client_id = option_value(&index, argc, argv,
			    "--oauth-client-id");
		else if (strcmp(argv[index], "--oauth-token-url") == 0)
			options.token_url = option_value(&index, argc, argv,
			    "--oauth-token-url");
		else if (strcmp(argv[index], "--daemon") == 0)
			daemon_mode = 1;
		else if (strcmp(argv[index], "--runtime-dir") == 0)
			runtime_directory =
			    option_value(&index, argc, argv, "--runtime-dir");
		else if (strcmp(argv[index], "--follow") == 0)
			follow_logs = 1;
		else if (strcmp(argv[index], "--debug-json") == 0)
			options.debug_json = debug_json_compact;
		else if (strcmp(argv[index], "--debug-json=compact") == 0)
			options.debug_json = debug_json_compact;
		else if (strcmp(argv[index], "--debug-json=pretty") == 0)
			options.debug_json = debug_json_pretty;
		else if (strncmp(argv[index], "--debug-json=", 13) == 0) {
			(void)fprintf(stderr,
			    "invalid --debug-json format: %s\n",
			    argv[index] + 13);
			return 1;
		} else if (strcmp(argv[index], "--open") == 0)
			open = 1;
		else if (strcmp(argv[index], "--no-open") == 0)
			open = 0;
		else if (strcmp(argv[index], "--login-timeout-ms") == 0)
			login_timeout_value = option_value(&index, argc, argv,
			    "--login-timeout-ms");
		else if (strncmp(argv[index], "--login-timeout-ms=", 19) == 0)
			login_timeout_value = argv[index] + 19;
		else if (strcmp(argv[index], "--help") == 0 ||
		    strcmp(argv[index], "-h") == 0) {
			usage(stdout);
			return 0;
		} else if (strcmp(argv[index], "--version") == 0) {
			(void)printf("%s\n", PACKAGE_VERSION);
			return 0;
		} else {
			usage(stderr);
			return 1;
		}
		if (index >= argc || argv[index] == NULL)
			return 1;
	}
	if (options.port != NULL &&
	    parse_positive_number(options.port, 65535UL, &port_number) == -1) {
		(void)fprintf(stderr,
		    "invalid port \"%s\" (expected a number from 1 to 65535)\n",
		    options.port);
		return 1;
	}
	if (login_timeout_value != NULL &&
	    parse_positive_number(login_timeout_value, (unsigned long)INT_MAX,
		&login_timeout) == -1) {
		(void)fprintf(stderr,
		    "invalid login timeout \"%s\" (expected a number from 1 to "
		    "%d)\n",
		    login_timeout_value, INT_MAX);
		return 1;
	}
	if (strcmp(command, "login") == 0) {
		if (daemon_mode || follow_logs || runtime_directory != NULL) {
			usage(stderr);
			return 1;
		}
		return run_login(&options, open, (int)login_timeout);
	}
	if (strcmp(command, "status") == 0 || strcmp(command, "stop") == 0 ||
	    strcmp(command, "logs") == 0) {
		/*
		** Lifecycle commands never inspect runtime.json as proof of life.
		** daemon.c connects to the private control socket, so stale metadata
		** cannot make status or stop report a process that is not listening.
		*/
		if (daemon_mode || options.host != NULL ||
		    options.port != NULL || options.models != NULL ||
		    options.base_url != NULL || options.codex_version != NULL ||
		    options.auth_file != NULL || options.client_id != NULL ||
		    options.token_url != NULL ||
		    options.debug_json != debug_json_disabled ||
		    (follow_logs && strcmp(command, "logs") != 0)) {
			usage(stderr);
			return 1;
		}
		if (strcmp(command, "status") == 0)
			index = daemon_status(runtime_directory, stdout, error,
			    sizeof(error));
		else if (strcmp(command, "stop") == 0)
			index = daemon_stop(runtime_directory, stdout, error,
			    sizeof(error));
		else
			index = daemon_logs(runtime_directory, follow_logs,
			    stdout, error, sizeof(error));
		if (index == -1) {
			(void)fprintf(stderr, "%s\n", error);
			return 1;
		}
		return 0;
	}
	if (strcmp(command, "serve") != 0 || follow_logs) {
		usage(stderr);
		return 1;
	}
	if (options.host != NULL && strcmp(options.host, "127.0.0.1") != 0 &&
	    strcmp(options.host, "localhost") != 0 &&
	    strcmp(options.host, "::1") != 0)
		(void)fprintf(stderr,
		    "Warning: this proxy is exposed to your network.\n");
	if (options.debug_json != debug_json_disabled)
		(void)fprintf(stderr,
		    "Warning: --debug-json logs prompts and "
		    "conversation history to stderr.\n");
	/*
	** Foreground serve passes no control endpoint and therefore keeps its
	** existing synchronous behavior.  --daemon delegates all fork, lock,
	** readiness, and log-redirection work to daemon_serve.
	*/
	if (daemon_mode) {
		if (daemon_serve(&options, runtime_directory, error,
			sizeof(error)) == -1) {
			(void)fprintf(stderr, "%s\n", error);
			return 1;
		}
	} else if (proxy_serve(&options, NULL, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		return 1;
	}
	return 0;
}
