#include "test.h"
#include "util.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int
request_port(const char *port, const char *request, char *response,
    size_t response_length)
{
	struct sockaddr_in	address;
	int			fd;
	ssize_t		count;
	size_t		length;

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
	    (count = read(fd, response + length, response_length - length - 1)) > 0)
		length += (size_t)count;
	response[length] = '\0';
	close(fd);
	return 0;
}

int
main(void)
{
	char	path[128];
	char	port[16];
	char	response[4096];
	pid_t	pid;
	int	status;

	(void)snprintf(path, sizeof(path), "/tmp/oaioauthc-proxy-%ld.json",
	    (long)getpid());
	(void)snprintf(port, sizeof(port), "%d", 14000 + (int)(getpid() % 1000));
	CHECK(write_private_file(path,
	    "{\"tokens\":{\"access_token\":\"access\",\"account_id\":\"acct_1\"}}") == 0);
	pid = fork();
	CHECK(pid != -1);
	if (pid == 0) {
		execl("../src/oaioauthc", "oaioauthc", "serve", "--port", port,
		    "--oauth-file", path, "--models", "gpt-test,gpt-other", (char *)NULL);
		_exit(127);
	}
	sleep(1);
	CHECK(request_port(port, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
	    response, sizeof(response)) == 0);
	CHECK(strstr(response, "200 OK") != NULL);
	CHECK(strstr(response, "\"replay_state\":\"stateless\"") != NULL);
	CHECK(request_port(port, "GET /v1/models HTTP/1.1\r\nHost: localhost\r\n\r\n",
	    response, sizeof(response)) == 0);
	CHECK(strstr(response, "\"id\":\"gpt-test\"") != NULL);
	CHECK(strstr(response, "\"id\":\"gpt-other\"") != NULL);
	CHECK(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\ncontent-length: 2\r\n\r\n{}",
	    response, sizeof(response)) == 0);
	CHECK(strstr(response, "404 Error") != NULL);
	CHECK(request_port(port, "POST /missing HTTP/1.1\r\n"
	    "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
	    "2\r\n{}\r\n0\r\n\r\n", response, sizeof(response)) == 0);
	CHECK(strstr(response, "404 Error") != NULL);
	(void)kill(pid, SIGTERM);
	CHECK(waitpid(pid, &status, 0) == pid);
	(void)unlink(path);
	return 0;
}
