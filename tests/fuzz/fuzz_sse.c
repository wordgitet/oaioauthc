/*
** libFuzzer entry point for incremental Codex SSE normalization.
**
** One input is fed in data-dependent fragments to both streaming translators.
** Output is discarded after exercising callback and parser ownership paths.
*/

#include <stddef.h>
#include <stdint.h>

#include "sse.h"

/* Accept parser output without retaining unbounded generated data. */
static int
discard(const void *data, size_t length, void *argument)
{
	(void)data;
	(void)length;
	(void)argument;
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t length)
{
	struct sse_chat_stream     *chat;
	struct sse_response_stream *response;
	size_t			 offset;
	size_t			 fragment;

	if (length > 1024 * 1024)
		return (0);
	response = sse_response_stream_new(discard, NULL);
	chat = sse_chat_stream_new("fuzz-model", discard, NULL);
	if (response == NULL || chat == NULL)
		goto done;
	offset = 0;
	while (offset < length) {
		fragment = 1 + data[offset] % 31;
		if (fragment > length - offset)
			fragment = length - offset;
		if (sse_response_stream_feed(response, data + offset, fragment) ==
		    -1 || sse_chat_stream_feed(chat, data + offset, fragment) == -1)
			break;
		offset += fragment;
	}
	(void)sse_response_stream_finish(response);
	(void)sse_chat_stream_finish(chat);

done:
	sse_response_stream_free(response);
	sse_chat_stream_free(chat);
	return (0);
}
