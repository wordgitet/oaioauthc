#include "sse.h"
#include "test.h"

#include <string.h>

int
main(void)
{
	char	error[256];
	json_t	*response;
	const char	*stream;

	stream = "event: response.created\r\n"
	    "data: {\"response\":{\"id\":\"resp_1\",\"status\":\"in_progress\"}}\r\n\r\n"
	    "event: response.output_item.done\r\n"
	    "data: {\"item\":{\"id\":\"msg_1\",\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}}\r\n\r\n"
	    "event: response.completed\r\n"
	    "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[]}}\r\n\r\n";
	response = sse_collect_completed_response(stream, error, sizeof(error));
	CHECK(response != NULL);
	CHECK(strcmp(json_string_value(json_object_get(response, "id")), "resp_1") == 0);
	CHECK(strcmp(json_string_value(json_object_get(response, "status")), "completed") == 0);
	CHECK(json_array_size(json_object_get(response, "output")) == 1);
	json_decref(response);
	return 0;
}
