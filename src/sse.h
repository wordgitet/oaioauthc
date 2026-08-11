/*
** Incremental Codex SSE parsing and Chat Completions stream emission.
**
** A stream object consumes arbitrary byte fragments from one Responses event
** stream and emits framed Chat Completions chunks through its callback.  It
** owns its parser state, copies the model name, and borrows the callback and
** callback argument until sse_chat_stream_free.
*/

#ifndef OAIOAUTHC_SSE_H
#define OAIOAUTHC_SSE_H

#include <jansson.h>
#include <stddef.h>

struct sse_chat_stream;
struct sse_response_stream;

/* Write one framed Chat Completions SSE fragment; zero means success. */
typedef int (*sse_write_callback)(const void *, size_t, void *);
/* Observe one parsed upstream JSON event without taking ownership. */
typedef void (*sse_trace_callback)(json_t *, void *);

/* Return the completed Responses object reconstructed from buffered SSE. */
json_t *
sse_collect_completed_response(const char *, char *, size_t);
/* Allocate a Responses stream normalizer for one outgoing client stream. */
struct sse_response_stream *
sse_response_stream_new(sse_write_callback, void *);
/* Observe each parsed upstream event without changing conversion. */
void
sse_response_stream_set_trace(struct sse_response_stream *, sse_trace_callback,
    void *);
/* Feed arbitrary upstream bytes and replace an empty terminal output array. */
int
sse_response_stream_feed(struct sse_response_stream *, const void *, size_t);
/* Consume a final partial block and require a completed response event. */
int
sse_response_stream_finish(struct sse_response_stream *);
/* Release all parser state and collected output items. */
void
sse_response_stream_free(struct sse_response_stream *);
/* Allocate a translator for one outgoing Chat Completions stream. */
struct sse_chat_stream *
sse_chat_stream_new(const char *, sse_write_callback, void *);
/* Observe each parsed upstream event without changing conversion. */
void
sse_chat_stream_set_trace(struct sse_chat_stream *, sse_trace_callback, void *);
/* Feed arbitrary upstream bytes and retain unfinished event data internally. */
int
sse_chat_stream_feed(struct sse_chat_stream *, const void *, size_t);
/* Consume a final partial block and require an explicit upstream completion. */
int
sse_chat_stream_finish(struct sse_chat_stream *);
/* Release all parser, model, tool, and pending-byte allocations. */
void
sse_chat_stream_free(struct sse_chat_stream *);

#endif
