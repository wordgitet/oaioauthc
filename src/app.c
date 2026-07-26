#include "app.h"
#include "auth.h"
#include "proxy.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void
usage(FILE *stream)
{
	(void)fprintf(stream,
	    "Usage:\n"
	    "  oaioauthc serve [--host HOST] [--port PORT] [--models IDS]\n"
	    "                  [--codex-version VERSION] [--base-url URL]\n"
	    "                  [--oauth-file PATH]\n"
	    "  oaioauthc login [--oauth-file PATH] [--no-open]\n");
}

static const char
*option_value(int *index, int argc, char **argv, const char *name)
{
	if (*index + 1 >= argc) {
		(void)fprintf(stderr, "%s requires a value\n", name);
		*index = argc;
		return NULL;
	}
	(*index)++;
	return argv[*index];
}

static int
open_browser(const char *url)
{
	pid_t	pid;

	pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		execlp("xdg-open", "xdg-open", url, (char *)NULL);
		_exit(127);
	}
	return 0;
}

static int
listen_callback(void)
{
	struct sockaddr_in	address;
	int			fd;
	int			one;

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

static char
*query_value(const char *target, const char *name)
{
	const char	*cursor;
	const char	*end;
	const char	*equal;
	const char	*query;
	struct buffer	value;
	char		decoded;
	int		high;
	int		low;

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

static int
send_callback_response(int fd, int status, const char *content_type,
    const char *body)
{
	char	header[256];
	int	length;

	length = snprintf(header, sizeof(header),
	    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
	    "Connection: close\r\n\r\n", status, status == 200 ? "OK" :
	    "Bad Request", content_type, strlen(body));
	if (length < 0 || (size_t)length >= sizeof(header))
		return -1;
	if (write_all(fd, header, (size_t)length) == -1)
		return -1;
	return write_all(fd, body, strlen(body));
}

static int
run_login(const struct proxy_options *options, int should_open)
{
	int			listen_fd;
	int			client_fd;
	char			request[8192];
	ssize_t		count;
	size_t			used;
	struct oauth_request	oauth;
	struct auth_session	session;
	char			*code;
	char			*method;
	char			*state;
	char			*target;
	char			*version;
	char			error[256];
	const char		*path;
	const char		*body;
	int			result;

	memset(&oauth, 0, sizeof(oauth));
	memset(&session, 0, sizeof(session));
	listen_fd = listen_callback();
	if (listen_fd == -1) {
		(void)fprintf(stderr, "login needs http://localhost:1455/auth/callback: %s\n",
		    strerror(errno));
		return 1;
	}
	if (oauth_request_create("http://localhost:1455/auth/callback",
	    options->client_id, &oauth, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		close(listen_fd);
		return 1;
	}
	(void)fprintf(stderr, "OpenAI OAuth login URL: %s\n", oauth.authorization_url);
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
		count = read(client_fd, request + used, sizeof(request) - used - 1);
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
	    target[strlen("/auth/callback")] != '\0') || version == NULL ||
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
	body = "<html><body>Sign-in complete. Return to your terminal.</body></html>";
	(void)send_callback_response(client_fd, 200,
	    "text/html; charset=utf-8", body);
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
	path = options->auth_file == NULL ? auth_default_file() : options->auth_file;
	if (auth_save(path, &session, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		auth_session_free(&session);
		return 1;
	}
	auth_session_free(&session);
	(void)fprintf(stderr, "Credentials saved to %s\n", path);
	return 0;
}

int
app_main(int argc, char **argv)
{
	struct proxy_options	options;
	const char		*command;
	int			index;
	int			open;
	char			error[256];

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		(void)fprintf(stderr, "could not ignore SIGPIPE: %s\n",
		    strerror(errno));
		return 1;
	}
	memset(&options, 0, sizeof(options));
	command = argc > 1 && argv[1][0] != '-' ? argv[1] : "serve";
	index = strcmp(command, "serve") == 0 && argc > 1 && argv[1][0] == '-' ?
	    1 : 2;
	open = 1;
	for (; index < argc; index++) {
		if (strcmp(argv[index], "--host") == 0)
			options.host = option_value(&index, argc, argv, "--host");
		else if (strcmp(argv[index], "--port") == 0)
			options.port = option_value(&index, argc, argv, "--port");
		else if (strcmp(argv[index], "--models") == 0)
			options.models = option_value(&index, argc, argv, "--models");
		else if (strcmp(argv[index], "--codex-version") == 0)
			options.codex_version = option_value(&index, argc, argv, "--codex-version");
		else if (strcmp(argv[index], "--base-url") == 0)
			options.base_url = option_value(&index, argc, argv, "--base-url");
		else if (strcmp(argv[index], "--oauth-file") == 0)
			options.auth_file = option_value(&index, argc, argv, "--oauth-file");
		else if (strcmp(argv[index], "--oauth-client-id") == 0)
			options.client_id = option_value(&index, argc, argv, "--oauth-client-id");
		else if (strcmp(argv[index], "--oauth-token-url") == 0)
			options.token_url = option_value(&index, argc, argv, "--oauth-token-url");
		else if (strcmp(argv[index], "--no-open") == 0)
			open = 0;
		else if (strcmp(argv[index], "--help") == 0) {
			usage(stdout);
			return 0;
		} else {
			usage(stderr);
			return 1;
		}
		if (index >= argc || argv[index] == NULL)
			return 1;
	}
	if (strcmp(command, "login") == 0)
		return run_login(&options, open);
	if (strcmp(command, "serve") != 0) {
		usage(stderr);
		return 1;
	}
	if (options.host != NULL && strcmp(options.host, "127.0.0.1") != 0 &&
	    strcmp(options.host, "localhost") != 0 && strcmp(options.host, "::1") != 0)
		(void)fprintf(stderr, "Warning: this proxy is exposed to your network.\n");
	if (proxy_serve(&options, error, sizeof(error)) == -1) {
		(void)fprintf(stderr, "%s\n", error);
		return 1;
	}
	return 0;
}
