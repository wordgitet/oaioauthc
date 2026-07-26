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

json_t
*sse_collect_completed_response(const char *stream, char *error, size_t length)
{
	char	*copy;
	char	*cursor;
	char	*block;
	char	*source;
	char	*destination;
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
	latest = NULL;
	cursor = copy;
	while (cursor != NULL) {
		char *data;
		char *next;
		json_error_t json_error;
		json_t *event;
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
		response = json_object_get(event, "response");
		if (json_is_object(response)) {
			json_decref(latest);
			latest = json_deep_copy(response);
		}
		json_decref(event);
	}
	free(copy);
	if (latest == NULL)
		set_error(error, length, "no completed response found in SSE stream");
	return latest;
}
