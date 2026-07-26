#include "util.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do {						\
	if (!(condition)) {						\
		(void)fprintf(stderr, "%s:%d: check failed: %s\n",	\
		    __FILE__, __LINE__, #condition);			\
		goto cleanup;						\
	}								\
} while (0)

static int
reserve_port(char *port, size_t length)
{
	struct sockaddr_in	address;
	socklen_t		address_length;
	int			fd;
	int			result;

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
	if (result == 0 && snprintf(port, length, "%u",
	    (unsigned int)ntohs(address.sin_port)) >= (int)length)
		result = -1;
	close(fd);
	return result;
}

static int
request_port(const char *port, const char *request, char *response,
    size_t response_length)
{
	struct sockaddr_in	address;
	int			fd;
	ssize_t			count;
	size_t			length;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons((unsigned short)atoi(port));
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1 ||
	    write_all(fd, request, strlen(request)) == -1) {
		close(fd);
		return -1;
	}
	length = 0;
	while (length + 1 < response_length &&
	    (count = read(fd, response + length,
	    response_length - length - 1)) > 0)
		length += (size_t)count;
	response[length] = '\0';
	close(fd);
	return 0;
}

static int
wait_for_proxy(const char *port, char *response, size_t length)
{
	struct timespec	delay;
	int		attempt;

	delay.tv_sec = 0;
	delay.tv_nsec = 10000000;
	for (attempt = 0; attempt < 200; attempt++) {
		if (request_port(port, "GET /health HTTP/1.1\r\n"
		    "Host: localhost\r\n\r\n", response, length) == 0)
			return 0;
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

int
main(void)
{
	char	path[] = "/tmp/oaioauthc-proxy-XXXXXX";
	char	port[16];
	char	response[4096];
	pid_t	pid;
	int	fd;
	int	result;
	int	status;

	pid = -1;
	result = 1;
	fd = mkstemp(path);
	REQUIRE(fd != -1);
	REQUIRE(close(fd) == 0);
	REQUIRE(write_private_file(path,
	    "{\"tokens\":{\"access_token\":\"access\","
	    "\"account_id\":\"acct_1\"}}") == 0);
	REQUIRE(reserve_port(port, sizeof(port)) == 0);
	pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		execl("../src/oaioauthc", "oaioauthc", "serve", "--port", port,
		    "--oauth-file", path, "--models", "gpt-test,gpt-other",
		    (char *)NULL);
		_exit(127);
	}
	REQUIRE(wait_for_proxy(port, response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "200 OK") != NULL);
	REQUIRE(strstr(response, "\"replay_state\":\"stateless\"") != NULL);
	REQUIRE(request_port(port, "GET /v1/models HTTP/1.1\r\n"
	    "Host: localhost\r\n\r\n", response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "\"id\":\"gpt-test\"") != NULL);
	REQUIRE(strstr(response, "\"id\":\"gpt-other\"") != NULL);
	REQUIRE(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\ncontent-length: 2\r\n\r\n{}",
	    response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	REQUIRE(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
	    "2\r\n{}\r\n0\r\n\r\n", response, sizeof(response)) == 0);
	REQUIRE(strstr(response, "404 Error") != NULL);
	result = 0;

cleanup:
	if (pid > 0) {
		(void)kill(pid, SIGTERM);
		(void)waitpid(pid, &status, 0);
	}
	(void)unlink(path);
	return result;
}
