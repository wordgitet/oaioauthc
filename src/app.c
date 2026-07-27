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
** The callback listener is deliberately restricted to 127.0.0.1:1455 and
** accepts exactly one request.  Its parser recognizes only the request line
** and query parameters needed for the OAuth redirect.  Public HTTP parsing,
** request limits, and route dispatch belong to proxy.c instead.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"
#include "auth.h"
#include "config.h"
#include "proxy.h"
#include "util.h"

/* Print the complete public command grammar to a diagnostic stream. */
static void
usage(FILE *stream)
{
	(void)fprintf(stream,
	    "Usage:\n"
	    "  oaioauthc serve [-p PORT] [--host HOST] [--models IDS]\n"
	    "                  [--codex-version VERSION] [--base-url URL]\n"
	    "                  [--oauth-file PATH]\n"
	    "                  [--debug-json[=compact|pretty]]\n"
	    "  oaioauthc login [--oauth-file PATH] [--open|--no-open]\n"
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
** Ask the desktop opener to visit url without making login depend on it.
**
** The child is intentionally not waited for: browsers often remain attached
** to the opener, and the loopback callback is the actual completion signal.
*/
static int
open_browser(const char *url)
{
	pid_t pid;

	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		execlp("xdg-open", "xdg-open", url, (char *)NULL);
		_exit(127);
	}
	return 0;
}

/*
** Open the fixed loopback listener used by the OAuth redirect URI.
**
** Binding INADDR_LOOPBACK, rather than all interfaces, prevents another host
** from submitting an authorization code to a local login attempt.
*/
static int
listen_callback(void)
{
	struct sockaddr_in address;
	int		   fd;
	int		   one;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	one = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(1455);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    listen(fd, 1) == -1) {
		close(fd);
		return -1;
	}
	return fd;
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
run_login(const struct proxy_options *options, int should_open)
{
	int		     listen_fd;
	int		     client_fd;
	char		     request[8192];
	ssize_t		     count;
	size_t		     used;
	struct oauth_request oauth;
	struct auth_session  session;
	char		    *code;
	char		    *method;
	char		    *state;
	char		    *target;
	char		    *version;
	char		     error[256];
	const char	    *path;
	const char	    *body;
	int		     result;

	/*
	 * The state comparison binds the one local redirect to this PKCE request.
	 * Do it before exchanging the code, since the callback listener is not an
	 * authenticated HTTP endpoint.
	 */
	memset(&oauth, 0, sizeof(oauth));
	memset(&session, 0, sizeof(session));
	listen_fd = listen_callback();
	if (listen_fd == -1) {
		(void)fprintf(stderr,
		    "login needs http://localhost:1455/auth/callback: %s\n",
		    strerror(errno));
		return 1;
	}
	if (oauth_request_create("http://localhost:1455/auth/callback",
		options->client_id, &oauth, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		close(listen_fd);
		return 1;
	}
	(void)fprintf(stderr, "OpenAI OAuth login URL: %s\n",
	    oauth.authorization_url);
	if (should_open)
		(void)open_browser(oauth.authorization_url);
	client_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);
	if (client_fd == -1) {
		oauth_request_free(&oauth);
		return 1;
	}
	used = 0;
	while (used + 1 < sizeof(request)) {
		count =
		    read(client_fd, request + used, sizeof(request) - used - 1);
		if (count == -1 && errno == EINTR)
			continue;
		if (count <= 0)
			break;
		used += (size_t)count;
		request[used] = '\0';
		if (strstr(request, "\r\n\r\n") != NULL)
			break;
	}
	request[used] = '\0';
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
		free(state);
		oauth_request_free(&oauth);
		close(client_fd);
		return 1;
	}
	body =
	    "<html><body>Sign-in complete. Return to your terminal.</body></html>";
	(void)send_callback_response(client_fd, 200, "text/html; charset=utf-8",
	    body);
	close(client_fd);
	result = oauth_exchange_code(code, oauth.code_verifier,
	    "http://localhost:1455/auth/callback", options->client_id,
	    options->token_url, &session, error, sizeof(error));
	free(code);
	free(state);
	oauth_request_free(&oauth);
	if (result == -1) {
		(void)fprintf(stderr, "%s\n", error);
		auth_session_free(&session);
		return 1;
	}
	path = options->auth_file == NULL ? auth_default_file()
					  : options->auth_file;
	if (auth_save(path, &session, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		auth_session_free(&session);
		return 1;
	}
	auth_session_free(&session);
	(void)fprintf(stderr, "Credentials saved to %s\n", path);
	return 0;
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
	int		     index;
	int		     open;
	char		     error[256];
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
	if (strcmp(command, "login") == 0)
		return run_login(&options, open);
	if (strcmp(command, "serve") != 0) {
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
	if (proxy_serve(&options, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		return 1;
	}
	return 0;
}
