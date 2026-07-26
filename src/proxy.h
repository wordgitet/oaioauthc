#ifndef OAIOAUTHC_PROXY_H
#define OAIOAUTHC_PROXY_H

#include <stddef.h>

enum debug_json_format {
	debug_json_disabled,
	debug_json_compact,
	debug_json_pretty
};

struct proxy_options {
	const char	*auth_file;
	const char	*host;
	const char	*port;
	const char	*base_url;
	const char	*codex_version;
	const char	*models;
	const char	*client_id;
	const char	*token_url;
	enum debug_json_format	debug_json;
};

int	proxy_serve(const struct proxy_options *, char *, size_t);

#endif
