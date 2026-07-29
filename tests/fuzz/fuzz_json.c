/*
** libFuzzer entry point for exact-length JSON parsing and conversions.
**
** The harness accepts arbitrary binary bytes, keeps the parser's length-aware
** boundary intact, and exercises mutable request normalization on deep copies.
** Every Jansson reference created here is released before returning.
*/

#include <stddef.h>
#include <stdint.h>

#include "json.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t length)
{
	char   error[256];
	json_t *chat;
	json_t *copy;
	json_t *response;
	json_t *value;

	if (length > 1024 * 1024)
		return (0);
	value = json_load_buffer_checked(data, length, error, sizeof(error));
	if (value == NULL)
		return (0);
	if (json_is_object(value)) {
		copy = json_deep_copy(value);
		if (copy != NULL) {
			(void)json_normalize_response_request(copy, 0, error,
			    sizeof(error));
			json_decref(copy);
		}
		response = json_chat_to_responses(value, error, sizeof(error));
		if (response != NULL)
			json_decref(response);
		chat = json_response_to_chat(value, value, error, sizeof(error));
		if (chat != NULL)
			json_decref(chat);
	}
	json_decref(value);
	return (0);
}
