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
#include <stdint.h>

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

/*
** The short-lived values returned by the headless device authorization
** endpoint.  The server supplies the device-auth id and user code, while this
** structure owns their copied allocations.  Neither is a bearer credential,
** but both are still released promptly after polling.  interval is the
** server's suggested delay between pending polls in seconds.  deadline_ms is
** an internal monotonic deadline shared by the request and polling phases.
*/
struct oauth_device_code {
	char	     *verification_url;
	char	     *user_code;
	char	     *device_auth_id;
	int64_t	      deadline_ms;
	unsigned long interval;
};

/* Return non-zero when a synchronous OAuth transfer should be cancelled. */
typedef int (*oauth_cancel_callback)(void *);

/* Return the cached default CODEX_HOME/auth.json or ~/.codex/auth.json path. */
const char *
auth_default_file(void);
/* Return the default OpenAI OAuth issuer used by browser and device login. */
const char *
oauth_default_issuer(void);
/* Release every auth_session allocation and reset all members to NULL. */
void
auth_session_free(struct auth_session *);
/* Load usable Codex credentials; session owns results on success. */
int
auth_load(const char *, struct auth_session *, char *, size_t);
/* Atomically merge session credentials into an auth.json file. */
int
auth_save(const char *, const struct auth_session *, char *, size_t);
/* Install session credentials only while the destination remains absent. */
int
auth_save_new(const char *, const struct auth_session *, char *, size_t);
/* Return non-zero when a refresh should precede an upstream request. */
int
auth_session_needs_refresh(const struct auth_session *);
/* Refresh session through OAuth and persist it to path on success. */
int
auth_refresh(const char *, const char *, const char *, struct auth_session *,
    char *, size_t);
/* Build a PKCE authorization request; request owns all outputs on success. */
int
oauth_request_create(const char *, const char *, const char *,
    struct oauth_request *, char *, size_t);
/* Release all oauth_request allocations and reset its members. */
void
oauth_request_free(struct oauth_request *);
/* Exchange one validated authorization code; session owns credentials. */
int
oauth_exchange_code(const char *, const char *, const char *, const char *,
    const char *, const char *, oauth_cancel_callback, void *,
    struct auth_session *, char *, size_t);
/* Request a short-lived device code from an issuer. */
int
oauth_device_code_request(const char *, const char *, int,
    oauth_cancel_callback, void *, struct oauth_device_code *, char *, size_t);
/* Release every device-code allocation and reset it for safe reuse. */
void
oauth_device_code_free(struct oauth_device_code *);
/* Poll a device code, exchange its authorization code, and fill session. */
int
oauth_device_code_poll(const char *, const char *, const char *,
    const struct oauth_device_code *, oauth_cancel_callback, void *,
    struct auth_session *, char *, size_t);

#endif
