#ifndef OAIOAUTHC_SSE_H
#define OAIOAUTHC_SSE_H

#include <jansson.h>
#include <stddef.h>

struct sse_chat_stream;

typedef int (*sse_write_callback)(const void *, size_t, void *);

json_t	*sse_collect_completed_response(const char *, char *, size_t);
struct sse_chat_stream	*sse_chat_stream_new(const char *, int,
	    sse_write_callback, void *);
int	sse_chat_stream_feed(struct sse_chat_stream *, const void *, size_t);
int	sse_chat_stream_finish(struct sse_chat_stream *);
void	sse_chat_stream_free(struct sse_chat_stream *);

#endif
