/*
** Configuration and entry point for the local OpenAI-compatible proxy.
**
** proxy_serve borrows this configuration for its complete blocking lifetime.
** The default listener is loopback-only.  NULL model/version values request
** discovery rather than selecting a model or hardcoding a Codex release.
*/

#ifndef OAIOAUTHC_PROXY_H
#define OAIOAUTHC_PROXY_H

#include <stddef.h>

/* Controls opt-in diagnostic JSON formatting; disabled is the safe default. */
enum debug_json_format {
	debug_json_disabled,
	debug_json_compact,
	debug_json_pretty
};

/*
** Immutable configuration borrowed by proxy_serve for the server lifetime.
**
** NULL fields select local-only defaults or automatic Codex discovery.  The
** caller retains every string for as long as proxy_serve can run.
*/
struct proxy_options {
	const char	      *auth_file;
	const char	      *host;
	const char	      *port;
	const char	      *base_url;
	const char	      *codex_version;
	const char	      *models;
	const char	      *client_id;
	const char	      *token_url;
	enum debug_json_format debug_json;
	int		       show_http_response;
};

/* Handle one accepted local control connection in the listener process. */
typedef int (*proxy_control_callback)(int, void *);

/* Optional local control endpoint and readiness notification for a daemon. */
struct proxy_control {
	int		       fd;
	proxy_control_callback callback;
	void		      *argument;
	int (*ready)(void *);
};

/* Bind, announce, and serve until a fatal setup or accept error is reported. */
int
proxy_serve(const struct proxy_options *, const struct proxy_control *, char *,
    size_t);

#endif
