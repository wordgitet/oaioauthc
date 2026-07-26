#ifndef OAIOAUTHC_HTTP_H
#define OAIOAUTHC_HTTP_H

#include <stddef.h>

struct http_response {
	long	status;
	char	*body;
	char	*content_type;
};

typedef int (*http_write_callback)(const void *, size_t, void *);

int	http_post_json(const char *, const char *, const char *, const char *,
	    const char *, struct http_response *, char *, size_t);
int	http_post_json_stream(const char *, const char *, const char *,
	    const char *, const char *, http_write_callback, void *,
	    struct http_response *, char *, size_t);
int	http_post_form(const char *, const char *, struct http_response *, char *,
	    size_t);
int	http_get(const char *, const char *, const char *, struct http_response *,
	    char *, size_t);
void	http_response_free(struct http_response *);
char	*http_form_encode(const char *);

#endif
