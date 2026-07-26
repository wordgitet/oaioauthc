#include "sse.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_EVENT_SIZE (1024 * 1024)

struct sse_tool {
	char	*item_id;
	size_t	index;
	int	arguments_seen;
};

struct sse_chat_stream {
	struct buffer		pending;
	char			*model;
	char			*id;
	struct sse_tool		*tools;
	size_t			tool_count;
	sse_write_callback	write;
	void			*argument;
	time_t			created;
	int			include_usage;
	int			role_sent;
	int			done;
};

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

static int
emit_json(struct sse_chat_stream *stream, json_t *value)
{
	struct buffer	line;
	char		*text;
	int		result;

	text = json_dumps(value, JSON_COMPACT);
	if (text == NULL)
		return -1;
	buffer_init(&line);
	result = buffer_append_string(&line, "data: ");
	if (result == 0)
		result = buffer_append_string(&line, text);
	if (result == 0)
		result = buffer_append_string(&line, "\n\n");
	free(text);
	if (result == 0)
		result = stream->write(line.data, line.len, stream->argument);
	buffer_free(&line);
	return result;
}

static int
emit_chunk(struct sse_chat_stream *stream, json_t *delta,
    const char *finish_reason)
{
	json_t	*choice;
	json_t	*choices;
	json_t	*chunk;
	json_t	*finish;
	int	result;

	finish = finish_reason == NULL ? json_null() :
	    json_string(finish_reason);
	choice = json_pack("{s:i,s:O,s:o}", "index", 0, "delta", delta,
	    "finish_reason", finish);
	if (choice == NULL)
		return -1;
	choices = json_pack("[o]", choice);
	chunk = json_pack("{s:s,s:s,s:I,s:s,s:o}", "id", stream->id,
	    "object", "chat.completion.chunk", "created",
	    (json_int_t)stream->created, "model", stream->model, "choices",
	    choices);
	if (chunk == NULL)
		return -1;
	result = emit_json(stream, chunk);
	json_decref(chunk);
	return result;
}

static int
emit_role(struct sse_chat_stream *stream)
{
	json_t	*delta;
	int	result;

	if (stream->role_sent)
		return 0;
	delta = json_pack("{s:s,s:s}", "role", "assistant", "content", "");
	if (delta == NULL)
		return -1;
	result = emit_chunk(stream, delta, NULL);
	json_decref(delta);
	if (result == 0)
		stream->role_sent = 1;
	return result;
}

static struct sse_tool *
find_tool(struct sse_chat_stream *stream, const char *item_id)
{
	size_t	index;

	if (item_id == NULL)
		return NULL;
	for (index = 0; index < stream->tool_count; index++) {
		if (strcmp(stream->tools[index].item_id, item_id) == 0)
			return &stream->tools[index];
	}
	return NULL;
}

static int
emit_tool_start(struct sse_chat_stream *stream, json_t *item)
{
	struct sse_tool	*next;
	struct sse_tool	*tool;
	const char	*item_id;
	const char	*call_id;
	const char	*name;
	json_t		*delta;
	int		result;

	item_id = json_string_value(json_object_get(item, "id"));
	call_id = json_string_value(json_object_get(item, "call_id"));
	name = json_string_value(json_object_get(item, "name"));
	if (item_id == NULL || call_id == NULL || name == NULL)
		return 0;
	if (find_tool(stream, item_id) != NULL)
		return 0;
	next = realloc(stream->tools,
	    (stream->tool_count + 1) * sizeof(*stream->tools));
	if (next == NULL)
		return -1;
	stream->tools = next;
	tool = &stream->tools[stream->tool_count];
	tool->item_id = oaio_strdup(item_id);
	if (tool->item_id == NULL)
		return -1;
	tool->index = stream->tool_count++;
	tool->arguments_seen = 0;
	delta = json_pack("{s:[{s:I,s:s,s:s,s:{s:s,s:s}}]}",
	    "tool_calls", "index", (json_int_t)tool->index, "id", call_id,
	    "type", "function", "function", "name", name, "arguments", "");
	if (delta == NULL)
		return -1;
	result = emit_role(stream);
	if (result == 0)
		result = emit_chunk(stream, delta, NULL);
	json_decref(delta);
	return result;
}

static int
emit_tool_arguments(struct sse_chat_stream *stream, const char *item_id,
    const char *arguments)
{
	struct sse_tool	*tool;
	json_t		*delta;
	int		result;

	tool = find_tool(stream, item_id);
	if (tool == NULL || arguments == NULL || arguments[0] == '\0')
		return 0;
	delta = json_pack("{s:[{s:I,s:{s:s}}]}", "tool_calls", "index",
	    (json_int_t)tool->index, "function", "arguments", arguments);
	if (delta == NULL)
		return -1;
	result = emit_chunk(stream, delta, NULL);
	json_decref(delta);
	if (result == 0)
		tool->arguments_seen = 1;
	return result;
}

static int
emit_usage(struct sse_chat_stream *stream, json_t *response)
{
	json_t	*upstream;
	json_t	*usage;
	json_t	*chunk;
	int	result;

	if (!stream->include_usage)
		return 0;
	upstream = json_object_get(response, "usage");
	if (!json_is_object(upstream))
		return 0;
	usage = json_pack("{s:I,s:I,s:I}", "prompt_tokens",
	    json_integer_value(json_object_get(upstream, "input_tokens")),
	    "completion_tokens",
	    json_integer_value(json_object_get(upstream, "output_tokens")),
	    "total_tokens",
	    json_integer_value(json_object_get(upstream, "total_tokens")));
	chunk = json_pack("{s:s,s:s,s:I,s:s,s:[],s:o}", "id", stream->id,
	    "object", "chat.completion.chunk", "created",
	    (json_int_t)stream->created, "model", stream->model, "choices",
	    "usage", usage);
	if (chunk == NULL)
		return -1;
	result = emit_json(stream, chunk);
	json_decref(chunk);
	return result;
}

static int
finish_chat_stream(struct sse_chat_stream *stream, json_t *response)
{
	json_t	*delta;
	int	result;

	if (stream->done)
		return 0;
	result = emit_role(stream);
	delta = json_object();
	if (result == 0 && delta == NULL)
		result = -1;
	if (result == 0)
		result = emit_chunk(stream, delta, stream->tool_count > 0 ?
		    "tool_calls" : "stop");
	json_decref(delta);
	if (result == 0 && response != NULL)
		result = emit_usage(stream, response);
	if (result == 0)
		result = stream->write("data: [DONE]\n\n", 14, stream->argument);
	if (result == 0)
		stream->done = 1;
	return result;
}

static int
process_event(struct sse_chat_stream *stream, const char *data)
{
	const char	*type;
	const char	*item_id;
	const char	*delta_text;
	json_error_t	error;
	json_t		*event;
	json_t		*item;
	json_t		*response;
	struct sse_tool	*tool;
	int		result;

	if (strcmp(data, "[DONE]") == 0)
		return finish_chat_stream(stream, NULL);
	event = json_loads(data, 0, &error);
	if (event == NULL)
		return 0;
	result = 0;
	type = json_string_value(json_object_get(event, "type"));
	item = json_object_get(event, "item");
	response = json_object_get(event, "response");
	if (type != NULL && strcmp(type, "response.created") == 0 &&
	    json_is_object(response)) {
		const char *id;

		id = json_string_value(json_object_get(response, "id"));
		if (id != NULL) {
			char *next;

			next = oaio_strdup(id);
			if (next == NULL)
				result = -1;
			else {
				free(stream->id);
				stream->id = next;
			}
		}
	} else if (type != NULL &&
	    strcmp(type, "response.output_text.delta") == 0) {
		delta_text = json_string_value(json_object_get(event, "delta"));
		if (delta_text != NULL) {
			json_t *delta;

			delta = json_pack("{s:s}", "content", delta_text);
			result = emit_role(stream);
			if (result == 0 && delta == NULL)
				result = -1;
			if (result == 0)
				result = emit_chunk(stream, delta, NULL);
			json_decref(delta);
		}
	} else if (type != NULL &&
	    strcmp(type, "response.output_item.added") == 0 &&
	    strcmp(json_string_value(json_object_get(item, "type")) == NULL ?
	    "" : json_string_value(json_object_get(item, "type")),
	    "function_call") == 0) {
		result = emit_tool_start(stream, item);
	} else if (type != NULL &&
	    strcmp(type, "response.function_call_arguments.delta") == 0) {
		item_id = json_string_value(json_object_get(event, "item_id"));
		delta_text = json_string_value(json_object_get(event, "delta"));
		result = emit_tool_arguments(stream, item_id, delta_text);
	} else if (type != NULL &&
	    strcmp(type, "response.output_item.done") == 0 &&
	    json_is_object(item)) {
		result = emit_tool_start(stream, item);
		item_id = json_string_value(json_object_get(item, "id"));
		tool = find_tool(stream, item_id);
		if (result == 0 && tool != NULL && !tool->arguments_seen)
			result = emit_tool_arguments(stream, item_id,
			    json_string_value(json_object_get(item, "arguments")));
	} else if (type != NULL &&
	    strcmp(type, "response.completed") == 0) {
		result = finish_chat_stream(stream, response);
	}
	json_decref(event);
	return result;
}

static int
process_block(struct sse_chat_stream *stream, char *block)
{
	char	*line;
	char	*next;

	line = block;
	while (line != NULL) {
		next = strchr(line, '\n');
		if (next != NULL)
			*next++ = '\0';
		if (strncmp(line, "data:", 5) == 0) {
			line += 5;
			while (*line == ' ')
				line++;
			return process_event(stream, line);
		}
		line = next;
	}
	return 0;
}

struct sse_chat_stream *
sse_chat_stream_new(const char *model, int include_usage,
    sse_write_callback callback, void *argument)
{
	struct sse_chat_stream	*stream;

	stream = calloc(1, sizeof(*stream));
	if (stream == NULL)
		return NULL;
	buffer_init(&stream->pending);
	stream->model = oaio_strdup(model == NULL ? "" : model);
	stream->id = oaio_strdup("chatcmpl_local");
	if (stream->model == NULL || stream->id == NULL) {
		sse_chat_stream_free(stream);
		return NULL;
	}
	stream->created = time(NULL);
	stream->include_usage = include_usage;
	stream->write = callback;
	stream->argument = argument;
	return stream;
}

int
sse_chat_stream_feed(struct sse_chat_stream *stream, const void *data,
    size_t length)
{
	const char	*source;
	char		*separator;
	size_t		index;
	size_t		consumed;

	source = data;
	for (index = 0; index < length; index++) {
		if (source[index] != '\r' &&
		    buffer_append(&stream->pending, source + index, 1) == -1)
			return -1;
	}
	if (stream->pending.len > MAX_EVENT_SIZE)
		return -1;
	while ((separator = strstr(stream->pending.data, "\n\n")) != NULL) {
		*separator = '\0';
		consumed = (size_t)(separator - stream->pending.data) + 2;
		if (process_block(stream, stream->pending.data) == -1)
			return -1;
		memmove(stream->pending.data, stream->pending.data + consumed,
		    stream->pending.len - consumed);
		stream->pending.len -= consumed;
		stream->pending.data[stream->pending.len] = '\0';
	}
	return 0;
}

int
sse_chat_stream_finish(struct sse_chat_stream *stream)
{
	if (stream->pending.len > 0 &&
	    process_block(stream, stream->pending.data) == -1)
		return -1;
	stream->pending.len = 0;
	if (stream->pending.data != NULL)
		stream->pending.data[0] = '\0';
	return stream->done ? 0 : -1;
}

void
sse_chat_stream_free(struct sse_chat_stream *stream)
{
	size_t	index;

	if (stream == NULL)
		return;
	for (index = 0; index < stream->tool_count; index++)
		free(stream->tools[index].item_id);
	free(stream->tools);
	free(stream->model);
	free(stream->id);
	buffer_free(&stream->pending);
	free(stream);
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
