#include "sse.h"
#include "test.h"
#include "util.h"

#include <string.h>

static int
capture(const void *data, size_t length, void *argument)
{
	return buffer_append(argument, data, length);
}

int
main(void)
{
	struct buffer	output;
	struct sse_chat_stream	*chat;
	char	error[256];
	json_t	*response;
	const char	*stream;
	size_t	split;

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

	stream = "data: {\"type\":\"response.created\",\"response\":{\"id\":"
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
	    "\"input_tokens\":3,\"output_tokens\":4,\"total_tokens\":7}}}\n\n";
	buffer_init(&output);
	chat = sse_chat_stream_new("gpt-test", 1, capture, &output);
	CHECK(chat != NULL);
	split = strlen(stream) / 2;
	CHECK(sse_chat_stream_feed(chat, stream, split) == 0);
	CHECK(sse_chat_stream_feed(chat, stream + split,
	    strlen(stream) - split) == 0);
	CHECK(sse_chat_stream_finish(chat) == 0);
	CHECK(strstr(output.data, "\"role\":\"assistant\"") != NULL);
	CHECK(strstr(output.data, "\"content\":\"hi\"") != NULL);
	CHECK(strstr(output.data, "\"id\":\"call_1\"") != NULL);
	CHECK(strstr(output.data, "\"arguments\":\"{\\\"q\\\":\"")
	    != NULL);
	CHECK(strstr(output.data, "\"finish_reason\":\"tool_calls\"") != NULL);
	CHECK(strstr(output.data, "\"prompt_tokens\":3") != NULL);
	CHECK(strstr(output.data, "data: [DONE]\n\n") != NULL);
	sse_chat_stream_free(chat);
	buffer_free(&output);
	return 0;
}
