/*
 * Request and response shape tests for the OpenAI/Codex JSON adapter.
 */

#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "test.h"

/*
** Cover normalization, discovered lite-model defaults, replay rejection, and
** both directions of Chat/Responses history translation in one local test.
*/
int
main(void)
{
	char	error[256];
	json_t *request;
	json_t *chat;
	json_t *converted;
	json_t *model;
	int	use_lite;

	request = json_load_string_checked(
	    "{\"model\":\"gpt-5.2\",\"input\":\"Hello\","
	    "\"max_output_tokens\":5}",
	    error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_normalize_response_request(request, 1, error,
		  sizeof(error)) == 0);
	CHECK(json_is_false(json_object_get(request, "store")));
	CHECK(json_is_true(json_object_get(request, "stream")));
	CHECK(json_object_get(request, "max_output_tokens") == NULL);
	CHECK(json_is_array(json_object_get(request, "input")));
	CHECK(json_array_size(json_object_get(request, "include")) == 1);
	json_decref(request);

	request = json_load_string_checked(
	    "{\"model\":\"gpt-5.2\",\"input\":\"Hello\",\"verbosity\":\"high\","
	    "\"reasoning_effort\":\"medium\",\"max_tokens\":8,"
	    "\"max_completion_tokens\":9,\"max_output_tokens\":10,"
	    "\"response_format\":{\"type\":\"json_schema\",\"json_schema\":{"
	    "\"name\":\"answer\",\"strict\":true,\"schema\":{\"type\":\"object\"}}}}",
	    error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_normalize_response_request(request, 1, error,
		  sizeof(error)) == 0);
	CHECK(json_object_get(request, "verbosity") == NULL);
	CHECK(json_object_get(request, "reasoning_effort") == NULL);
	CHECK(json_object_get(request, "response_format") == NULL);
	CHECK(json_object_get(request, "max_tokens") == NULL);
	CHECK(json_object_get(request, "max_completion_tokens") == NULL);
	CHECK(json_object_get(request, "max_output_tokens") == NULL);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(request, "text"), "verbosity")),
		  "high") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(request, "reasoning"), "effort")),
		  "medium") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(json_object_get(request, "text"),
			     "format"),
			 "type")),
		  "json_schema") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(json_object_get(request, "text"),
			     "format"),
			 "name")),
		  "answer") == 0);
	json_decref(request);

	request = json_load_string_checked(
	    "{\"model\":\"gpt-test\",\"input\":\"Hello\",\"verbosity\":\"high\"}",
	    error, sizeof(error));
	model = json_load_string_checked(
	    "{\"slug\":\"gpt-test\",\"support_verbosity\":false}", error,
	    sizeof(error));
	CHECK(request != NULL && model != NULL);
	CHECK(json_normalize_response_request(request, 1, error,
		  sizeof(error)) == 0);
	CHECK(json_apply_model_defaults(request, model, &use_lite, error,
		  sizeof(error)) == 0);
	CHECK(json_object_get(json_object_get(request, "text"), "verbosity") ==
	    NULL);
	json_decref(model);
	json_decref(request);

	request = json_load_string_checked(
	    "{\"model\":\"gpt-lite\",\"input\":\"Hello\","
	    "\"instructions\":\"Be concise\",\"tools\":[{\"type\":"
	    "\"function\",\"name\":\"lookup\"}]}",
	    error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_normalize_response_request(request, 1, error,
		  sizeof(error)) == 0);
	model = json_load_string_checked(
	    "{\"slug\":\"gpt-lite\",\"use_responses_lite\":true,"
	    "\"default_reasoning_level\":\"medium\","
	    "\"support_verbosity\":true,\"default_verbosity\":\"low\"}",
	    error, sizeof(error));
	CHECK(model != NULL);
	CHECK(json_apply_model_defaults(request, model, &use_lite, error,
		  sizeof(error)) == 0);
	CHECK(use_lite == 1);
	CHECK(json_object_get(request, "tools") == NULL);
	CHECK(json_array_size(json_object_get(request, "input")) == 3);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(request, "reasoning"), "context")),
		  "all_turns") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(request, "text"), "verbosity")),
		  "low") == 0);
	json_decref(model);
	json_decref(request);

	request = json_load_string_checked(
	    "{\"previous_response_id\":\"resp_1\"}", error, sizeof(error));
	CHECK(request != NULL);
	CHECK(json_has_replay_state(request) == 1);
	json_decref(request);

	chat = json_load_string_checked(
	    "{\"model\":\"gpt-5.2\",\"messages\":[{\"role\":\"system\","
	    "\"content\":\"Be concise\"},{\"role\":\"user\",\"content\":"
	    "\"Hello\"}],\"stop\":[\"END\"],\"parallel_tool_calls\":false,"
	    "\"reasoning_effort\":\"high\",\"tool_choice\":{\"type\":"
	    "\"function\",\"function\":{\"name\":\"lookup\"}}}",
	    error, sizeof(error));
	CHECK(chat != NULL);
	converted = json_chat_to_responses(chat, error, sizeof(error));
	CHECK(converted != NULL);
	CHECK(json_array_size(json_object_get(converted, "input")) == 2);
	CHECK(strcmp(json_string_value(json_object_get(converted, "model")),
		  "gpt-5.2") == 0);
	CHECK(json_is_array(json_object_get(converted, "stop")));
	CHECK(json_is_false(json_object_get(converted, "parallel_tool_calls")));
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(converted, "reasoning"), "effort")),
		  "high") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(converted, "tool_choice"), "name")),
		  "lookup") == 0);
	json_decref(converted);
	json_decref(chat);

	chat = json_load_string_checked(
	    "{\"model\":\"gpt-test\",\"verbosity\":\"low\","
	    "\"response_format\":{\"type\":\"json_object\"},"
	    "\"function_call\":{\"name\":\"lookup\"},\"functions\":[{"
	    "\"name\":\"lookup\",\"description\":\"Find a value\","
	    "\"strict\":true,\"parameters\":{\"type\":\"object\"}}],"
	    "\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}",
	    error, sizeof(error));
	CHECK(chat != NULL);
	converted = json_chat_to_responses(chat, error, sizeof(error));
	CHECK(converted != NULL);
	CHECK(json_normalize_response_request(converted, 1, error,
		  sizeof(error)) == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(converted, "text"), "verbosity")),
		  "low") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(json_object_get(converted, "text"),
			     "format"),
			 "type")),
		  "json_object") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_object_get(converted, "tool_choice"), "name")),
		  "lookup") == 0);
	CHECK(json_is_true(json_object_get(
	    json_array_get(json_object_get(converted, "tools"), 0), "strict")));
	json_decref(converted);
	json_decref(chat);

	chat = json_load_string_checked(
	    "{\"model\":\"gpt-test\",\"stream\":true,\"messages\":["
	    "{\"role\":\"user\",\"content\":\"Hello\"},"
	    "{\"role\":\"assistant\",\"content\":\"Hi there\"},"
	    "{\"role\":\"user\",\"content\":\"Continue\"}]}",
	    error, sizeof(error));
	CHECK(chat != NULL);
	converted = json_chat_to_responses(chat, error, sizeof(error));
	CHECK(converted != NULL);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_array_get(
			     json_object_get(
				 json_array_get(
				     json_object_get(converted, "input"), 0),
				 "content"),
			     0),
			 "type")),
		  "input_text") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_array_get(
			     json_object_get(
				 json_array_get(
				     json_object_get(converted, "input"), 1),
				 "content"),
			     0),
			 "type")),
		  "output_text") == 0);
	CHECK(strcmp(json_string_value(json_object_get(
			 json_array_get(
			     json_object_get(
				 json_array_get(
				     json_object_get(converted, "input"), 2),
				 "content"),
			     0),
			 "type")),
		  "input_text") == 0);
	json_decref(converted);
	json_decref(chat);

	chat = json_load_string_checked(
	    "{\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}", error,
	    sizeof(error));
	CHECK(chat != NULL);
	CHECK(json_chat_to_responses(chat, error, sizeof(error)) == NULL);
	json_decref(chat);
	return 0;
}
