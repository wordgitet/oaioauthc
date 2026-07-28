/*
** Server-Sent Events parsing and Responses-to-Chat-Completions streaming.
**
** Codex streams Responses events.  A Chat Completions client instead expects
** a sequence of chat.completion.chunk objects followed by "data: [DONE]".
** This module bridges those protocols without assuming that one network read
** contains one SSE event or even one complete line.
**
** sse_chat_stream retains an unfinished event block, strips CR so CRLF and LF
** streams behave identically, and processes data only after a blank-line
** separator.  It tracks tool calls by Codex item id, so argument deltas and a
** later completed item cannot produce duplicate Chat Completions tool calls.
** The writer callback owns transport delivery; a callback failure is fatal to
** the conversion because clients must not receive a malformed partial stream.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sse.h"
#include "util.h"

#define MAX_EVENT_SIZE (1024 * 1024)

/* One Codex function-call item and its Chat Completions array position. */
struct sse_tool {
	char  *item_id;
	size_t index;
	int    arguments_seen;
};

/*
** Stateful translator for one upstream Responses event stream.
**
** pending stores bytes after the last complete SSE block.  tools associates
** Codex item ids with stable Chat Completions indices.  role_sent and done
** enforce the required stream ordering even when Codex omits optional events.
** The callback and argument are borrowed for the stream lifetime.
*/
struct sse_chat_stream {
	struct buffer	   pending;
	char		  *model;
	char		  *id;
	struct sse_tool	  *tools;
	size_t		   tool_count;
	sse_write_callback write;
	void		  *argument;
	time_t		   created;
	int		   role_sent;
	int		   done;
};

/* Set a short parse diagnostic in the caller-owned error buffer. */
static void
set_error(char *error, size_t length, const char *message)
{
	if (error != NULL && length > 0)
		(void)snprintf(error, length, "%s", message);
}

/*
** Deep-copy an output item into items, replacing an earlier item with its id.
**
** Codex can describe an item incrementally and later provide a completed copy.
** Deduplication preserves the most complete representation for non-streaming
** response collection without changing its original output position.
*/
static int
collect_output_item(json_t *items, json_t *item)
{
	const char *id;
	const char *existing_id;
	json_t	   *copy;
	json_t	   *existing;
	size_t	    index;

	if (!json_is_object(item))
		return 0;
	id = json_string_value(json_object_get(item, "id"));
	if (id == NULL)
		return 0;
	copy = json_deep_copy(item);
	if (copy == NULL)
		return -1;
	json_array_foreach(items, index, existing)
	{
		existing_id = json_string_value(
		    json_object_get(existing, "id"));
		if (existing_id != NULL && strcmp(existing_id, id) == 0)
			return json_array_set_new(items, index, copy);
	}
	return json_array_append_new(items, copy);
}

/* Serialize value as one complete SSE data block and write it to the client. */
static int
emit_json(struct sse_chat_stream *stream, json_t *value)
{
	struct buffer line;
	char	     *text;
	int	      result;

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

/* Build and emit one OpenAI chat.completion.chunk around the supplied delta. */
static int
emit_chunk(struct sse_chat_stream *stream, json_t *delta,
    const char *finish_reason)
{
	json_t *choice;
	json_t *choices;
	json_t *chunk;
	json_t *finish;
	int	result;

	finish = finish_reason == NULL ? json_null()
				       : json_string(finish_reason);
	choice = json_pack("{s:i,s:O,s:o}", "index", 0, "delta", delta,
	    "finish_reason", finish);
	if (choice == NULL)
		return -1;
	choices = json_pack("[o]", choice);
	chunk = json_pack("{s:s,s:s,s:I,s:s,s:o}", "id", stream->id, "object",
	    "chat.completion.chunk", "created", (json_int_t)stream->created,
	    "model", stream->model, "choices", choices);
	if (chunk == NULL)
		return -1;
	result = emit_json(stream, chunk);
	json_decref(chunk);
	return result;
}

/* Emit the mandatory assistant role exactly once before content/tool deltas. */
static int
emit_role(struct sse_chat_stream *stream)
{
	json_t *delta;
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

/* Find the stable Chat tool-call slot belonging to a Codex output item id. */
static struct sse_tool *
find_tool(struct sse_chat_stream *stream, const char *item_id)
{
	size_t index;

	if (item_id == NULL)
		return NULL;
	for (index = 0; index < stream->tool_count; index++) {
		if (strcmp(stream->tools[index].item_id, item_id) == 0)
			return &stream->tools[index];
	}
	return NULL;
}

/*
** Emit the initial empty-arguments Chat tool-call delta for a Codex item.
**
** A repeated output_item.added or output_item.done event must not create a
** second call, so item_id is registered before the first client write.
*/
static int
emit_tool_start(struct sse_chat_stream *stream, json_t *item)
{
	struct sse_tool *next;
	struct sse_tool *tool;
	const char	*item_id;
	const char	*call_id;
	const char	*name;
	json_t		*delta;
	int		 result;

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
	delta = json_pack("{s:[{s:I,s:s,s:s,s:{s:s,s:s}}]}", "tool_calls",
	    "index", (json_int_t)tool->index, "id", call_id, "type", "function",
	    "function", "name", name, "arguments", "");
	if (delta == NULL)
		return -1;
	result = emit_role(stream);
	if (result == 0)
		result = emit_chunk(stream, delta, NULL);
	json_decref(delta);
	return result;
}

/* Append one function argument delta to the previously registered tool call. */
static int
emit_tool_arguments(struct sse_chat_stream *stream, const char *item_id,
    const char *arguments)
{
	struct sse_tool *tool;
	json_t		*delta;
	int		 result;

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

/* Copy available upstream usage accounting into the final Chat stream chunk. */
static int
emit_usage(struct sse_chat_stream *stream, json_t *response)
{
	json_t *upstream;
	json_t *details;
	json_t *usage;
	json_t *chunk;
	int	result;

	upstream = json_object_get(response, "usage");
	if (!json_is_object(upstream))
		return 0;
	usage = json_pack("{s:I,s:I,s:I}", "prompt_tokens",
	    json_integer_value(json_object_get(upstream, "input_tokens")),
	    "completion_tokens",
	    json_integer_value(json_object_get(upstream, "output_tokens")),
	    "total_tokens",
	    json_integer_value(json_object_get(upstream, "total_tokens")));
	details = json_object_get(upstream, "input_tokens_details");
	if (json_is_integer(json_object_get(details, "cached_tokens")))
		json_object_set_new(usage, "prompt_tokens_details",
		    json_pack("{s:O}", "cached_tokens",
			json_object_get(details, "cached_tokens")));
	details = json_object_get(upstream, "output_tokens_details");
	if (json_is_integer(json_object_get(details, "reasoning_tokens")))
		json_object_set_new(usage, "completion_tokens_details",
		    json_pack("{s:O}", "reasoning_tokens",
			json_object_get(details, "reasoning_tokens")));
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

/*
** Finish a translated Chat stream once, including finish reason, usage, DONE.
**
** No further upstream event can cause output after done becomes true.  This
** guards both an explicit [DONE] block and a response.completed event.
*/
static int
finish_chat_stream(struct sse_chat_stream *stream, json_t *response)
{
	json_t *delta;
	int	result;

	if (stream->done)
		return 0;
	result = emit_role(stream);
	delta = json_object();
	if (result == 0 && delta == NULL)
		result = -1;
	if (result == 0)
		result = emit_chunk(stream, delta,
		    stream->tool_count > 0 ? "tool_calls" : "stop");
	json_decref(delta);
	if (result == 0 && response != NULL)
		result = emit_usage(stream, response);
	if (result == 0)
		result =
		    stream->write("data: [DONE]\n\n", 14, stream->argument);
	if (result == 0)
		stream->done = 1;
	return result;
}

/*
** Translate one complete Codex SSE data payload.
**
** Unknown event types are harmless and ignored for forward compatibility.
** Malformed JSON is likewise ignored because an upstream stream can include
** non-JSON control data; allocation and client-write failures remain fatal.
*/
static int
process_event(struct sse_chat_stream *stream, const char *data)
{
	const char	*type;
	const char	*item_id;
	const char	*delta_text;
	json_error_t	 error;
	json_t		*event;
	json_t		*item;
	json_t		*response;
	struct sse_tool *tool;
	int		 result;

	/* One complete Codex event may produce zero, one, or several chat chunks. */
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
		if (result == 0)
			result = emit_role(stream);
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
	    strcmp(json_string_value(json_object_get(item, "type")) == NULL
		    ? ""
		    : json_string_value(json_object_get(item, "type")),
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
			    json_string_value(
				json_object_get(item, "arguments")));
	} else if (type != NULL && strcmp(type, "response.completed") == 0) {
		result = finish_chat_stream(stream, response);
	}
	json_decref(event);
	return result;
}

/* Extract the first data: line from one complete SSE block and process it. */
static int
process_block(struct sse_chat_stream *stream, char *block)
{
	char *line;
	char *next;

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

/*
** Allocate a translator for one Chat Completions request.
**
** model is copied for every emitted chunk.  callback and argument are borrowed
** until sse_chat_stream_free, and the returned stream starts with a local id
** that is replaced if Codex sends response.created.
*/
struct sse_chat_stream *
sse_chat_stream_new(const char *model, sse_write_callback callback,
    void *argument)
{
	struct sse_chat_stream *stream;

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
	stream->write = callback;
	stream->argument = argument;
	return stream;
}

/*
** Feed arbitrary upstream transport bytes into the incremental translator.
**
** CR is discarded so both CRLF and LF framing use one parser.  Bytes after the
** final blank-line separator remain in pending for a later call; pending is
** capped so an upstream peer cannot make the worker retain unbounded memory.
*/
int
sse_chat_stream_feed(struct sse_chat_stream *stream, const void *data,
    size_t length)
{
	const char *source;
	char	   *separator;
	size_t	    index;
	size_t	    consumed;

	/* Transport writes may split any SSE line, so retain an incomplete block. */
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

/*
** Consume a final unterminated SSE block and require a completion signal.
**
** Returning -1 for a stream without [DONE] or response.completed prevents the
** proxy from reporting an apparently clean Chat completion after truncation.
*/
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

/* Release every owned stream allocation; safe for NULL and partial creation. */
void
sse_chat_stream_free(struct sse_chat_stream *stream)
{
	size_t index;

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

/*
** Collect the completed Responses object from a buffered Codex SSE reply.
**
** The latest response object is authoritative, while item events fill an empty
** output array when Codex delivered the items separately.  The caller owns the
** returned reference; a missing completed response sets error and returns NULL.
*/
json_t *
sse_collect_completed_response(const char *stream, char *error, size_t length)
{
	char   *copy;
	char   *cursor;
	char   *block;
	char   *source;
	char   *destination;
	json_t *items;
	json_t *latest;

	/* Non-streaming Codex replies use SSE too; retain only the final response. */
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
		char	    *data;
		char	    *next;
		json_error_t json_error;
		json_t	    *event;
		json_t	    *item;
		json_t	    *response;
		const char  *type;

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
		type = json_string_value(json_object_get(event, "type"));
		if (type != NULL && strcmp(type, "response.completed") == 0 &&
		    json_is_object(response)) {
			json_decref(latest);
			latest = json_deep_copy(response);
		}
		json_decref(event);
	}
	free(copy);
	if (latest == NULL) {
		set_error(error, length,
		    "no completed response found in SSE stream");
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
