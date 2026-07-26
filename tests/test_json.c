#include "json.h"
#include "test.h"

#include <stdlib.h>
#include <string.h>

int
main(void)
{
	char	error[256];
	json_t	*request;
	json_t	*chat;
	json_t	*converted;

	request = json_load_string_checked("{\"model\":\"gpt-5.2\",\"input\":\"Hello\",\"max_output_tokens\":5}",
	    error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_normalize_response_request(request, 1, error, sizeof(error)) == 0);
	CHECK(json_is_false(json_object_get(request, "store")));
	CHECK(json_is_true(json_object_get(request, "stream")));
	CHECK(json_object_get(request, "max_output_tokens") == NULL);
	CHECK(json_is_array(json_object_get(request, "input")));
	CHECK(json_array_size(json_object_get(request, "include")) == 1);
	json_decref(request);

	request = json_load_string_checked("{\"previous_response_id\":\"resp_1\"}",
	    error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_has_replay_state(request) == 1);
	json_decref(request);

	chat = json_load_string_checked("{\"model\":\"gpt-5.2\",\"messages\":[{\"role\":\"system\",\"content\":\"Be concise\"},{\"role\":\"user\",\"content\":\"Hello\"}]}",
	    error, sizeof(error));
	CHECK(chat != NULL);
	converted = json_chat_to_responses(chat, error, sizeof(error));
	CHECK(converted != NULL);
	CHECK(json_array_size(json_object_get(converted, "input")) == 2);
	CHECK(strcmp(json_string_value(json_object_get(converted, "model")), "gpt-5.2") == 0);
	json_decref(converted);
	json_decref(chat);
	return 0;
}
