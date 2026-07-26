#ifndef OAIOAUTHC_PROXY_H
#define OAIOAUTHC_PROXY_H

#include <stddef.h>

struct proxy_options {
	const char	*auth_file;
	const char	*host;
	const char	*port;
	const char	*base_url;
	const char	*codex_version;
	const char	*models;
	const char	*client_id;
	const char	*token_url;
};

int	proxy_serve(const struct proxy_options *, char *, size_t);

#endif
