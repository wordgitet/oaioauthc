/*
** OAuth session ownership and PKCE exchange interface.
**
** Every successful load, refresh, or code exchange transfers heap-owned token
** strings to auth_session.  oauth_request similarly owns its authorization
** URL, state, and verifier.  The corresponding free routines accept partial
** or zeroed values, which keeps error cleanup simple at each caller.
*/

#ifndef OAIOAUTHC_AUTH_H
#define OAIOAUTHC_AUTH_H

#include <stddef.h>

/*
** Credentials and routing metadata loaded from Codex auth.json.
**
** access_token and account_id are required for Codex requests.  refresh_token
** permits renewal, id_token is a fallback source of account metadata, and
** last_refresh supports conservative renewal for opaque access tokens.
*/
struct auth_session {
	char *access_token;
	char *refresh_token;
	char *id_token;
	char *account_id;
	char *last_refresh;
};

/*
** One pending PKCE authorization request.
**
** state must match the loopback callback exactly.  code_verifier is retained
** only until the authorization code exchange completes.
*/
struct oauth_request {
	char *authorization_url;
	char *state;
	char *code_verifier;
};

/* Return the cached default CODEX_HOME/auth.json or ~/.codex/auth.json path. */
const char *
auth_default_file(void);
/* Release every auth_session allocation and reset all members to NULL. */
void
auth_session_free(struct auth_session *);
/* Load usable Codex credentials; session owns results on success. */
int
auth_load(const char *, struct auth_session *, char *, size_t);
/* Atomically merge session credentials into an auth.json file. */
int
auth_save(const char *, const struct auth_session *, char *, size_t);
/* Return non-zero when a refresh should precede an upstream request. */
int
auth_session_needs_refresh(const struct auth_session *);
/* Refresh session through OAuth and persist it to path on success. */
int
auth_refresh(const char *, const char *, const char *, struct auth_session *,
    char *, size_t);
/* Build a PKCE authorization request; request owns all outputs on success. */
int
oauth_request_create(const char *, const char *, struct oauth_request *, char *,
    size_t);
/* Release all oauth_request allocations and reset its members. */
void
oauth_request_free(struct oauth_request *);
/* Exchange one state-validated code; session owns credentials on success. */
int
oauth_exchange_code(const char *, const char *, const char *, const char *,
    const char *, struct auth_session *, char *, size_t);

#endif
