#include "sse.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
set_error(char *error, size_t length, const char *message)
{
	if (error != NULL && length > 0)
		(void)snprintf(error, length, "%s", message);
}

static int
collect_output_item(json_t *items, json_t *item)
{
	const char	*id;
	const char	*existing_id;
	json_t		*copy;
	json_t		*existing;
	size_t		index;

	if (!json_is_object(item))
		return 0;
	id = json_string_value(json_object_get(item, "id"));
	if (id == NULL)
		return 0;
	copy = json_deep_copy(item);
	if (copy == NULL)
		return -1;
	json_array_foreach(items, index, existing) {
		existing_id = json_string_value(json_object_get(existing, "id"));
		if (existing_id != NULL && strcmp(existing_id, id) == 0)
			return json_array_set_new(items, index, copy);
	}
	return json_array_append_new(items, copy);
}

json_t
*sse_collect_completed_response(const char *stream, char *error, size_t length)
{
	char	*copy;
	char	*cursor;
	char	*block;
	char	*source;
	char	*destination;
	json_t	*items;
	json_t	*latest;

	copy = oaio_strdup(stream);
	if (copy == NULL)
		return NULL;
	destination = copy;
	for (source = copy; *source != '\0'; source++) {
		if (*source != '\r')
			*destination++ = *source;
	}
	*destination = '\0';
	items = json_array();
	if (items == NULL) {
		free(copy);
		return NULL;
	}
	latest = NULL;
	cursor = copy;
	while (cursor != NULL) {
		char *data;
		char *next;
		json_error_t json_error;
		json_t *event;
		json_t *item;
		json_t *response;

		next = strstr(cursor, "\n\n");
		if (next != NULL)
			*next = '\0';
		block = cursor;
		cursor = next == NULL ? NULL : next + 2;
		data = strstr(block, "data:");
		if (data == NULL)
			continue;
		data += 5;
		while (*data == ' ')
			data++;
		event = json_loads(data, 0, &json_error);
		if (event == NULL)
			continue;
		item = json_object_get(event, "item");
		if (collect_output_item(items, item) == -1) {
			json_decref(event);
			json_decref(items);
			json_decref(latest);
			free(copy);
			return NULL;
		}
		response = json_object_get(event, "response");
		if (json_is_object(response)) {
			json_decref(latest);
			latest = json_deep_copy(response);
		}
		json_decref(event);
	}
	free(copy);
	if (latest == NULL) {
		set_error(error, length, "no completed response found in SSE stream");
	} else if (json_array_size(items) > 0 &&
	    json_array_size(json_object_get(latest, "output")) == 0) {
		if (json_object_set(latest, "output", items) == -1) {
			json_decref(latest);
			latest = NULL;
		}
	}
	json_decref(items);
	return latest;
}
