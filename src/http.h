/*
** Bounded synchronous HTTP client interface.
**
** A successful call returns a response whose body and content_type are owned
** by the caller.  Streaming calls invoke the callback only for successful
** bodies; non-2xx bodies remain buffered.  Every result is released with
** http_response_free, including a partially initialized one after an error.
*/

#ifndef OAIOAUTHC_HTTP_H
#define OAIOAUTHC_HTTP_H

#include <stddef.h>

/* Buffered upstream response returned by the HTTP helpers. */
struct http_response {
	long  status;
	char *body;
	char *content_type;
};

/*
** Receive a successful streamed response fragment.
**
** Return zero after accepting data.  A non-zero return aborts the libcurl
** transfer and causes the corresponding HTTP helper to fail.
*/
typedef int (*http_write_callback)(const void *, size_t, void *);
/* Return non-zero when a synchronous transfer should stop promptly. */
typedef int (*http_cancel_callback)(void *);

/* POST one JSON body with optional Codex bearer/account/feature headers. */
int
http_post_json(const char *, const char *, const char *, const char *,
    const char *, struct http_response *, char *, size_t);
/* POST JSON and stream successful fragments to the supplied callback. */
int
http_post_json_stream(const char *, const char *, const char *, const char *,
    const char *, http_write_callback, void *, struct http_response *, char *,
    size_t);
/* POST an OAuth form body without Codex authorization headers. */
int
http_post_form(const char *, const char *, http_cancel_callback, void *,
    struct http_response *, char *, size_t);
/* GET an authenticated Codex endpoint into a bounded response. */
int
http_get(const char *, const char *, const char *, struct http_response *,
    char *, size_t);
/* Release response body/type allocations and reset response. */
void
http_response_free(struct http_response *);
/* Return an owned application/x-www-form-urlencoded encoding. */
char *
http_form_encode(const char *);

#endif
