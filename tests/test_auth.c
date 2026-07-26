#include "auth.h"
#include "test.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	char			path[128];
	char			error[256];
	struct auth_session	session;
	struct oauth_request	request;

	(void)snprintf(path, sizeof(path), "/tmp/oaioauthc-test-%ld.json",
	    (long)getpid());
	CHECK(write_private_file(path,
	    "{\"tokens\":{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"id_token\":\"id\",\"account_id\":\"acct_1\"}}") == 0);
	CHECK(auth_load(path, &session, error, sizeof(error)) == 0);
	CHECK(strcmp(session.access_token, "access") == 0);
	CHECK(strcmp(session.account_id, "acct_1") == 0);
	auth_session_free(&session);
	CHECK(write_private_file(path,
	    "{\"tokens\":{\"access_token\":\"header.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdF9qd3QifX0.signature\"}}") == 0);
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
	CHECK(oauth_request_create("http://localhost:1455/auth/callback", NULL,
	    &request, error, sizeof(error)) == 0);
	CHECK(strstr(request.authorization_url, "code_challenge_method=S256") != NULL);
	CHECK(request.state != NULL && request.code_verifier != NULL);
	oauth_request_free(&request);
	(void)unlink(path);
	return 0;
}
