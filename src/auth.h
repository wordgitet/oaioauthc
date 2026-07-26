#ifndef OAIOAUTHC_AUTH_H
#define OAIOAUTHC_AUTH_H

#include <stddef.h>

struct auth_session {
	char	*access_token;
	char	*refresh_token;
	char	*id_token;
	char	*account_id;
	char	*last_refresh;
};

struct oauth_request {
	char	*authorization_url;
	char	*state;
	char	*code_verifier;
};

const char	*auth_default_file(void);
void	auth_session_free(struct auth_session *);
int	auth_load(const char *, struct auth_session *, char *, size_t);
int	auth_save(const char *, const struct auth_session *, char *, size_t);
int	auth_session_needs_refresh(const struct auth_session *);
int	auth_refresh(const char *, const char *, const char *, struct auth_session *,
	    char *, size_t);
int	oauth_request_create(const char *, const char *, struct oauth_request *,
	    char *, size_t);
void	oauth_request_free(struct oauth_request *);
int	oauth_exchange_code(const char *, const char *, const char *, const char *,
	    const char *, struct auth_session *, char *, size_t);

#endif
