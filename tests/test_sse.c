/*
 * Incremental SSE parser and Chat Completions stream conversion tests.
 */

#include <string.h>

#include "sse.h"
#include "test.h"
#include "util.h"

/* Capture emitted Chat SSE bytes in a growable buffer for assertions. */
static int
capture(const void *data, size_t length, void *argument)
{
	return buffer_append(argument, data, length);
}

/*
** Verify buffered completion collection and a deliberately split live stream,
** including tool-call deltas, usage mapping, and terminal [DONE] framing.
*/
int
main(void)
{
	static const char binary_stream[] =
	    "data: {\"type\":\"response.completed\",\"response\":{"
	    "\"id\":\"resp_binary\",\"status\":\"completed\","
	    "\"output\":[]}}\n\n\0ignored";
	struct buffer		    output;
	struct sse_chat_stream	   *chat;
	struct sse_response_stream *responses;
	char			    error[256];
	json_t			   *response;
	const char		   *stream;
	size_t			    split;

	stream = "event: response.created\r\n"
		 "data: {\"response\":{\"id\":\"resp_1\",\"status\":"
		 "\"in_progress\"}}\r\n\r\n"
		 "event: response.output_item.done\r\n"
		 "data: {\"item\":{\"id\":\"msg_1\",\"type\":\"message\","
		 "\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}}"
		 "\r\n\r\n"
		 "event: response.completed\r\n"
		 "data: {\"type\":\"response.completed\",\"response\":{\"id\":"
		 "\"resp_1\",\"status\":\"completed\",\"output\":[]}}\r\n\r\n";
	response = sse_collect_completed_response(stream, error, sizeof(error));
	CHECK(response != NULL);
	CHECK(strcmp(json_string_value(json_object_get(response, "id")),
		  "resp_1") == 0);
	CHECK(strcmp(json_string_value(json_object_get(response, "status")),
		  "completed") == 0);
	CHECK(json_array_size(json_object_get(response, "output")) == 1);
	json_decref(response);

	stream =
	    "event: response.output_item.done\n"
	    "data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":"
	    "\"msg_2\",\"type\":\"message\",\"content\":[{\"type\":"
	    "\"output_text\",\"text\":\"hello\"}]}}\n\n"
	    "event: response.completed\n"
	    "data: {\"type\":\"response.completed\",\"response\":{\"id\":"
	    "\"resp_2\",\"status\":\"completed\",\"output\":[]}}\n\n";
	buffer_init(&output);
	responses = sse_response_stream_new(capture, &output);
	CHECK(responses != NULL);
	split = strlen(stream) / 2;
	CHECK(sse_response_stream_feed(responses, stream, split) == 0);
	CHECK(sse_response_stream_feed(responses, stream + split,
		  strlen(stream) - split) == 0);
	CHECK(sse_response_stream_finish(responses) == 0);
	CHECK(strstr(output.data, "event: response.completed") != NULL);
	CHECK(strstr(output.data, "\"output\":[{\"id\":\"msg_2\"") != NULL);
	sse_response_stream_free(responses);
	buffer_free(&output);

	stream =
	    "data: {\"type\":\"response.created\",\"response\":{\"id\":"
	    "\"resp_partial\",\"status\":\"in_progress\",\"output\":[]}}\n\n";
	response = sse_collect_completed_response(stream, error, sizeof(error));
	CHECK(response == NULL);
	CHECK(strstr(error, "no completed response") != NULL);

	/*
	** A raw NUL is not valid SSE and must not hide bytes after a completion.
	** Exercise the buffered collector and both incremental parser variants.
	*/
	response = sse_collect_completed_response_buffer(binary_stream,
	    sizeof(binary_stream) - 1, error, sizeof(error));
	CHECK(response == NULL);
	CHECK(strstr(error, "invalid binary data") != NULL);
	buffer_init(&output);
	responses = sse_response_stream_new(capture, &output);
	CHECK(responses != NULL);
	CHECK(sse_response_stream_feed(responses, binary_stream,
		  sizeof(binary_stream) - 1) == -1);
	CHECK(output.len == 0);
	sse_response_stream_free(responses);
	buffer_free(&output);
	buffer_init(&output);
	chat = sse_chat_stream_new("gpt-test", capture, &output);
	CHECK(chat != NULL);
	CHECK(sse_chat_stream_feed(chat, binary_stream,
		  sizeof(binary_stream) - 1) == -1);
	CHECK(output.len == 0);
	sse_chat_stream_free(chat);
	buffer_free(&output);

	stream =
	    "data: {\"type\":\"response.created\",\"response\":{\"id\":"
	    "\"resp_2\"}}\n\n"
	    "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n"
	    "data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":"
	    "\"item_1\",\"type\":\"function_call\",\"call_id\":\"call_1\","
	    "\"name\":\"lookup\"}}\n\n"
	    "data: {\"type\":\"response.function_call_arguments.delta\","
	    "\"item_id\":\"item_1\",\"delta\":\"{\\\"q\\\":\"}\n\n"
	    "data: {\"type\":\"response.function_call_arguments.delta\","
	    "\"item_id\":\"item_1\",\"delta\":\"\\\"x\\\"}\"}\n\n"
	    "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{"
	    "\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7,"
	    "\"input_tokens_details\":{\"cached_tokens\":1},"
	    "\"output_tokens_details\":{\"reasoning_tokens\":2}}}}\n\n";
	buffer_init(&output);
	chat = sse_chat_stream_new("gpt-test", capture, &output);
	CHECK(chat != NULL);
	split = strlen(stream) / 2;
	CHECK(sse_chat_stream_feed(chat, stream, split) == 0);
	CHECK(sse_chat_stream_feed(chat, stream + split,
		  strlen(stream) - split) == 0);
	CHECK(sse_chat_stream_finish(chat) == 0);
	CHECK(strstr(output.data, "\"role\":\"assistant\"") != NULL);
	CHECK(strstr(output.data, "\"content\":\"hi\"") != NULL);
	CHECK(strstr(output.data, "\"id\":\"call_1\"") != NULL);
	CHECK(strstr(output.data, "\"arguments\":\"{\\\"q\\\":\"") != NULL);
	CHECK(strstr(output.data, "\"finish_reason\":\"tool_calls\"") != NULL);
	CHECK(strstr(output.data, "\"prompt_tokens\":3") != NULL);
	CHECK(strstr(output.data, "\"cached_tokens\":1") != NULL);
	CHECK(strstr(output.data, "\"reasoning_tokens\":2") != NULL);
	CHECK(strstr(output.data, "data: [DONE]\n\n") != NULL);
	sse_chat_stream_free(chat);
	buffer_free(&output);
	return 0;
}
