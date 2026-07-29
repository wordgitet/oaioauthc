/*
** JSON shape conversion between OpenAI-compatible clients and Codex.
**
** This module does not perform I/O and does not retain conversation state.
** It receives Jansson values owned by the request worker, validates the
** OpenAI-compatible parts that Codex depends on, and rewrites them into the
** request and response shapes accepted by the upstream endpoint.
**
** Responses is the internal common representation.  Chat Completions input
** is expanded into an ordered Responses input array, including assistant
** output, tool calls, tool outputs, refusals, and image references.  Completed
** Responses output is collapsed back into one Chat Completions choice.  This
** explicit replay conversion is what keeps the proxy stateless.
**
** Model catalog entries supply defaults only when a client omits an option.
** They also identify models that need the Responses-lite layout, where tools
** and instructions become ordered developer input rather than top-level
** fields.
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "util.h"

/* Populate the optional caller diagnostic buffer without allocating. */
static void
set_error(char *error, size_t length, const char *format, ...)
{
	va_list ap;

	if (error == NULL || length == 0)
		return;
	va_start(ap, format);
	(void)vsnprintf(error, length, format, ap);
	va_end(ap);
}

/* Serialize a JSON value compactly; the caller owns the Jansson allocation. */
char *
json_dump_compact(json_t *value)
{
	return json_dumps(value, JSON_COMPACT);
}

/*
** Parse a NUL-terminated JSON string and report Jansson's parse detail.
**
** The caller receives one new reference on success and must decref it.  This
** helper is reserved for trusted NUL-terminated buffers; binary request bodies
** are parsed with length-aware APIs in their owning module.
*/
json_t *
json_load_string_checked(const char *text, char *error, size_t length)
{
	json_error_t json_error;
	json_t	    *value;

	value = json_loads(text, 0, &json_error);
	if (value == NULL)
		set_error(error, length, "invalid JSON: %s", json_error.text);
	return value;
}

/*
** Parse an exact-length JSON buffer and reject data hidden after embedded NULs.
**
** Network and file input is not inherently a C string.  Keeping the byte count
** through this boundary ensures Jansson validates every received byte instead
** of accepting a valid prefix that happens to precede a NUL.
*/
json_t *
json_load_buffer_checked(const void *data, size_t data_length, char *error,
    size_t length)
{
	json_error_t json_error;
	json_t	    *value;

	if (data == NULL && data_length != 0) {
		set_error(error, length, "invalid JSON buffer");
		return NULL;
	}
	value =
	    json_loadb(data == NULL ? "" : data, data_length, 0, &json_error);
	if (value == NULL)
		set_error(error, length, "invalid JSON: %s", json_error.text);
	return value;
}

/* Build a local OpenAI-compatible error envelope with an HTTP status field. */
json_t *
json_error_object(const char *message, const char *type, int status)
{
	json_t *error;
	json_t *body;

	error = json_pack("{s:s,s:s}", "message", message, "type", type);
	body = json_pack("{s:o,s:i}", "error", error, "status", status);
	return body;
}

/*
** Detect References that require a persistent Responses store.
**
** Codex through this proxy is deliberately stateless, so previous_response_id
** and item_reference input are rejected before normalizing the request.
*/
int
json_has_replay_state(json_t *request)
{
	json_t *input;
	size_t	index;
	json_t *item;

	if (json_is_string(json_object_get(request, "previous_response_id")))
		return 1;
	input = json_object_get(request, "input");
	if (!json_is_array(input))
		return 0;
	json_array_foreach(input, index, item)
	{
		const char *type;

		type = json_string_value(json_object_get(item, "type"));
		if (json_is_object(item) && type != NULL &&
		    strcmp(type, "item_reference") == 0 &&
		    json_is_string(json_object_get(item, "id")))
			return 1;
	}
	return 0;
}

/*
** Return request.text, allocating its object form for a compatibility alias.
**
** The caller borrows the returned object through request.  A replacement only
** occurs when a malformed or absent text member cannot hold nested settings.
*/
static json_t *
request_text_object(json_t *request)
{
	json_t *text;

	text = json_object_get(request, "text");
	if (json_is_object(text))
		return text;
	text = json_object();
	if (text == NULL)
		return NULL;
	if (json_object_set(request, "text", text) == -1) {
		json_decref(text);
		return NULL;
	}
	json_decref(text);
	return json_object_get(request, "text");
}

/*
** Check the documented Responses text verbosity levels before moving an alias.
**
** Validating locally prevents a client-only top-level field from becoming an
** opaque upstream Codex error after the proxy has already rewritten it.
*/
static int
valid_verbosity(json_t *value)
{
	const char *verbosity;

	verbosity = json_string_value(value);
	return verbosity != NULL &&
	    (strcmp(verbosity, "low") == 0 ||
		strcmp(verbosity, "medium") == 0 ||
		strcmp(verbosity, "high") == 0);
}

/*
** Translate documented compatibility aliases into their Responses equivalents.
**
** Open WebUI exposes some Chat-shaped settings even when configured to call
** /v1/responses.  The aliases handled here have exact Responses meanings.
** Canonical nested fields always win, so callers can safely send both forms
** during a gradual migration.  Token caps are deliberately discarded because
** the Codex OAuth endpoint does not accept output-token limit controls.
*/
static int
normalize_response_compatibility(json_t *request, char *error, size_t length)
{
	const char *type;
	json_t	   *format;
	json_t	   *reasoning;
	json_t	   *schema;
	json_t	   *text;
	json_t	   *value;

	value = json_object_get(request, "verbosity");
	if (value != NULL) {
		if (!valid_verbosity(value)) {
			set_error(error, length,
			    "`verbosity` must be `low`, `medium`, or `high`");
			return -1;
		}
		text = request_text_object(request);
		if (text == NULL ||
		    (json_object_get(text, "verbosity") == NULL &&
			json_object_set(text, "verbosity", value) == -1))
			goto fail;
		json_object_del(request, "verbosity");
	}
	value = json_object_get(request, "reasoning_effort");
	if (value != NULL) {
		if (!json_is_string(value)) {
			set_error(error, length,
			    "`reasoning_effort` must be a string");
			return -1;
		}
		reasoning = json_object_get(request, "reasoning");
		if (!json_is_object(reasoning)) {
			reasoning = json_object();
			if (reasoning == NULL ||
			    json_object_set(request, "reasoning", reasoning) ==
				-1) {
				json_decref(reasoning);
				goto fail;
			}
			json_decref(reasoning);
			reasoning = json_object_get(request, "reasoning");
		}
		if (json_object_get(reasoning, "effort") == NULL &&
		    json_object_set(reasoning, "effort", value) == -1)
			goto fail;
		json_object_del(request, "reasoning_effort");
	}
	format = json_object_get(request, "response_format");
	if (format != NULL) {
		if (!json_is_object(format) ||
		    !json_is_string(json_object_get(format, "type"))) {
			set_error(error, length,
			    "`response_format` must be an object with a `type`");
			return -1;
		}
		text = request_text_object(request);
		if (text == NULL)
			goto fail;
		if (json_object_get(text, "format") == NULL) {
			type = json_string_value(
			    json_object_get(format, "type"));
			if (strcmp(type, "text") == 0 ||
			    strcmp(type, "json_object") == 0) {
				value = json_pack("{s:s}", "type", type);
				if (value == NULL ||
				    json_object_set(text, "format", value) ==
					-1) {
					json_decref(value);
					goto fail;
				}
				json_decref(value);
			} else if (strcmp(type, "json_schema") == 0) {
				schema = json_object_get(format, "json_schema");
				if (!json_is_object(schema) ||
				    !json_is_string(
					json_object_get(schema, "name")) ||
				    !json_is_object(
					json_object_get(schema, "schema"))) {
					set_error(error, length,
					    "`response_format.json_schema` needs name and schema");
					return -1;
				}
				value =
				    json_pack("{s:s}", "type", "json_schema");
				if (value == NULL ||
				    json_object_set(value, "name",
					json_object_get(schema, "name")) ==
					-1 ||
				    json_object_set(value, "schema",
					json_object_get(schema, "schema")) ==
					-1 ||
				    (json_object_get(schema, "description") !=
					    NULL &&
					json_object_set(value, "description",
					    json_object_get(schema,
						"description")) == -1) ||
				    (json_object_get(schema, "strict") !=
					    NULL &&
					json_object_set(value, "strict",
					    json_object_get(schema,
						"strict")) == -1) ||
				    json_object_set(text, "format", value) ==
					-1) {
					json_decref(value);
					goto fail;
				}
				json_decref(value);
			} else {
				set_error(error, length,
				    "unsupported `response_format.type`");
				return -1;
			}
		}
		json_object_del(request, "response_format");
	}
	json_object_del(request, "max_tokens");
	json_object_del(request, "max_completion_tokens");
	json_object_del(request, "max_output_tokens");
	return 0;

fail:
	set_error(error, length, "could not normalize Responses compatibility");
	return -1;
}

/*
** Normalize one Responses request in place for the Codex backend.
**
** A string input becomes a user input_text message.  store is forced false,
** obsolete output-token aliases are removed, encrypted reasoning is requested
** for client-side replay, and force_stream can override a caller's choice.
** The caller retains ownership of request on both success and failure.
*/
int
json_normalize_response_request(json_t *request, int force_stream, char *error,
    size_t length)
{
	json_t *input;
	json_t *content;
	json_t *message;
	json_t *include;
	json_t *item;
	size_t	index;

	/* Codex is stateless and always needs encrypted reasoning in replays. */
	if (!json_is_object(request)) {
		set_error(error, length, "request body must be a JSON object");
		return -1;
	}
	if (!json_is_string(json_object_get(request, "model")) ||
	    json_string_length(json_object_get(request, "model")) == 0) {
		set_error(error, length, "`model` must be a non-empty string");
		return -1;
	}
	input = json_object_get(request, "input");
	if (json_is_string(input)) {
		content = json_pack("[{s:s,s:s}]", "type", "input_text", "text",
		    json_string_value(input));
		message =
		    json_pack("{s:s,s:o}", "role", "user", "content", content);
		input = json_array();
		json_array_append_new(input, message);
		json_object_set_new(request, "input", input);
	}
	if (!json_is_string(json_object_get(request, "instructions")))
		json_object_set_new(request, "instructions", json_string(""));
	json_object_set_new(request, "store", json_false());
	if (normalize_response_compatibility(request, error, length) == -1)
		return -1;
	include = json_object_get(request, "include");
	if (!json_is_array(include)) {
		include = json_array();
		json_object_set_new(request, "include", include);
	}
	json_array_foreach(include, index, item)
	{
		if (json_is_string(item) &&
		    strcmp(json_string_value(item),
			"reasoning.encrypted_content") == 0)
			break;
	}
	if (index == json_array_size(include))
		json_array_append_new(include,
		    json_string("reasoning.encrypted_content"));
	if (force_stream)
		json_object_set_new(request, "stream", json_true());
	return 0;
}

/* Return true when an input array already contains the expected type. */
static int
input_has_type(json_t *input, const char *expected)
{
	const char *type;
	json_t	   *item;
	size_t	    index;

	if (!json_is_array(input))
		return 0;
	json_array_foreach(input, index, item)
	{
		type = json_string_value(json_object_get(item, "type"));
		if (type != NULL && strcmp(type, expected) == 0)
			return 1;
	}
	return 0;
}

/*
** Apply discovered metadata for the selected model in place.
**
** Defaults never replace explicit reasoning effort or verbosity.  Lite models
** use a different request layout: tools and instructions are represented as
** leading developer inputs, context covers all turns, and parallel tool calls
** are disabled to match the upstream capability.
*/
int
json_apply_model_defaults(json_t *request, json_t *model, int *use_lite,
    char *error, size_t length)
{
	const char *default_effort;
	const char *default_verbosity;
	const char *instructions;
	json_t	   *input;
	json_t	   *item;
	json_t	   *next_input;
	json_t	   *reasoning;
	json_t	   *text;
	json_t	   *tools;
	size_t	    index;

	/* Catalog defaults fill omissions; client values take precedence. */
	*use_lite = json_is_true(json_object_get(model, "use_responses_lite"));
	default_effort = json_string_value(
	    json_object_get(model, "default_reasoning_level"));
	reasoning = json_object_get(request, "reasoning");
	if ((default_effort != NULL || *use_lite) &&
	    !json_is_object(reasoning)) {
		reasoning = json_object();
		if (reasoning == NULL ||
		    json_object_set_new(request, "reasoning", reasoning) == -1)
			goto fail;
	}
	if (json_is_object(reasoning) && default_effort != NULL &&
	    json_object_get(reasoning, "effort") == NULL &&
	    json_object_set_new(reasoning, "effort",
		json_string(default_effort)) == -1)
		goto fail;
	if (*use_lite &&
	    json_object_set_new(reasoning, "context",
		json_string("all_turns")) == -1)
		goto fail;
	default_verbosity = json_string_value(
	    json_object_get(model, "default_verbosity"));
	text = json_object_get(request, "text");
	if (json_is_false(json_object_get(model, "support_verbosity"))) {
		if (json_is_object(text))
			json_object_del(text, "verbosity");
	} else if (json_is_true(json_object_get(model, "support_verbosity")) &&
	    default_verbosity != NULL) {
		if (!json_is_object(text)) {
			text = json_object();
			if (text == NULL ||
			    json_object_set_new(request, "text", text) == -1)
				goto fail;
		}
		if (json_object_get(text, "verbosity") == NULL &&
		    json_object_set_new(text, "verbosity",
			json_string(default_verbosity)) == -1)
			goto fail;
	}
	if (!*use_lite)
		return 0;
	input = json_object_get(request, "input");
	next_input = json_array();
	if (next_input == NULL)
		goto fail;
	tools = json_object_get(request, "tools");
	if (json_is_array(tools) && json_array_size(tools) > 0 &&
	    !input_has_type(input, "additional_tools")) {
		item = json_pack("{s:s,s:s,s:O}", "type", "additional_tools",
		    "role", "developer", "tools", tools);
		if (item == NULL ||
		    json_array_append_new(next_input, item) == -1) {
			json_decref(next_input);
			goto fail;
		}
	}
	instructions = json_string_value(
	    json_object_get(request, "instructions"));
	if (instructions != NULL && instructions[0] != '\0') {
		item = json_pack("{s:s,s:[{s:s,s:s}]}", "role", "developer",
		    "content", "type", "input_text", "text", instructions);
		if (item == NULL ||
		    json_array_append_new(next_input, item) == -1) {
			json_decref(next_input);
			goto fail;
		}
	}
	if (json_is_array(input)) {
		json_array_foreach(input, index, item)
		{
			if (json_array_append(next_input, item) == -1) {
				json_decref(next_input);
				goto fail;
			}
		}
	}
	if (json_object_set_new(request, "input", next_input) == -1)
		goto fail;
	if (json_object_set_new(request, "instructions", json_string("")) ==
		-1 ||
	    json_object_set_new(request, "parallel_tool_calls", json_false()) ==
		-1)
		goto fail;
	json_object_del(request, "tools");
	return 0;

fail:
	set_error(error, length, "could not apply model defaults");
	return -1;
}

/*
** Convert one Chat Completions content value into Responses content parts.
**
** The returned array is a new reference.  Unsupported content parts are
** omitted rather than reinterpreted; callers preserve only text, refusal, and
** supported user image URLs.
*/
static json_t *
chat_content_to_input(json_t *content, int assistant)
{
	const char *text_type;
	json_t	   *part;
	json_t	   *result;
	size_t	    index;

	text_type = assistant ? "output_text" : "input_text";
	if (json_is_string(content))
		return json_pack("[{s:s,s:s}]", "type", text_type, "text",
		    json_string_value(content));
	if (!json_is_array(content))
		return json_array();
	result = json_array();
	json_array_foreach(content, index, part)
	{
		const char *type;

		if (!json_is_object(part))
			continue;
		type = json_string_value(json_object_get(part, "type"));
		if (type != NULL && strcmp(type, "text") == 0) {
			json_array_append_new(result,
			    json_pack("{s:s,s:s}", "type", text_type, "text",
				json_string_value(
				    json_object_get(part, "text"))));
		} else if (assistant && type != NULL &&
		    strcmp(type, "refusal") == 0 &&
		    json_is_string(json_object_get(part, "refusal"))) {
			json_array_append_new(result,
			    json_pack("{s:s,s:s}", "type", "refusal", "refusal",
				json_string_value(
				    json_object_get(part, "refusal"))));
		} else if (!assistant && type != NULL &&
		    strcmp(type, "image_url") == 0) {
			json_t *image;

			image = json_object_get(part, "image_url");
			if (json_is_object(image) &&
			    json_is_string(json_object_get(image, "url")))
				json_array_append_new(result,
				    json_pack("{s:s,s:s}", "type",
					"input_image", "image_url",
					json_string_value(
					    json_object_get(image, "url"))));
		}
	}
	return result;
}

/*
** Convert one legacy or modern Chat function declaration into a Responses tool.
**
** Both declarations have the same function object after the modern tools[]
** wrapper is removed.  Preserve the documented description, schema, and
** strictness fields without changing a caller-provided JSON schema.
*/
static json_t *
chat_function_to_response(json_t *function)
{
	json_t	   *converted;
	const char *name;

	if (!json_is_object(function))
		return NULL;
	name = json_string_value(json_object_get(function, "name"));
	if (name == NULL)
		return NULL;
	converted = json_pack("{s:s,s:s}", "type", "function", "name", name);
	if (converted == NULL)
		return NULL;
	if ((json_is_string(json_object_get(function, "description")) &&
		json_object_set(converted, "description",
		    json_object_get(function, "description")) == -1) ||
	    (json_is_object(json_object_get(function, "parameters")) &&
		json_object_set(converted, "parameters",
		    json_object_get(function, "parameters")) == -1) ||
	    (json_is_boolean(json_object_get(function, "strict")) &&
		json_object_set(converted, "strict",
		    json_object_get(function, "strict")) == -1)) {
		json_decref(converted);
		return NULL;
	}
	return converted;
}

/*
** Translate a complete Chat Completions request into a Responses request.
**
** The result owns newly created input and tool arrays but borrows compatible
** scalar values through Jansson reference counting.  Tool messages become
** function_call_output items, assistant tool calls become function_call items,
** and system/developer messages share the upstream developer role.
*/
json_t *
json_chat_to_responses(json_t *chat, char *error, size_t length)
{
	json_t *messages;
	json_t *input;
	json_t *message;
	json_t *result;
	json_t *tools;
	json_t *tool_choice;
	json_t *response_tools;
	json_t *legacy_functions;
	size_t	index;

	/* Rebuild history as Responses input because no server-side replay exists. */
	messages = json_object_get(chat, "messages");
	if (!json_is_string(json_object_get(chat, "model")) ||
	    json_string_length(json_object_get(chat, "model")) == 0) {
		set_error(error, length, "`model` must be a non-empty string");
		return NULL;
	}
	if (!json_is_array(messages)) {
		set_error(error, length, "`messages` must be an array");
		return NULL;
	}
	input = json_array();
	json_array_foreach(messages, index, message)
	{
		const char *role;
		json_t	   *converted;
		int	    assistant;

		if (!json_is_object(message) ||
		    !json_is_string(json_object_get(message, "role")))
			continue;
		role = json_string_value(json_object_get(message, "role"));
		if (strcmp(role, "tool") == 0) {
			json_t *call_id;
			json_t *content;

			call_id = json_object_get(message, "tool_call_id");
			content = json_object_get(message, "content");
			if (json_is_string(call_id))
				json_array_append_new(input,
				    json_pack("{s:s,s:s,s:o}", "type",
					"function_call_output", "call_id",
					json_string_value(call_id), "output",
					json_deep_copy(content)));
			continue;
		}
		assistant = strcmp(role, "assistant") == 0;
		converted = chat_content_to_input(
		    json_object_get(message, "content"), assistant);
		if (assistant &&
		    json_is_string(json_object_get(message, "refusal")))
			json_array_append_new(converted,
			    json_pack("{s:s,s:s}", "type", "refusal", "refusal",
				json_string_value(
				    json_object_get(message, "refusal"))));
		json_array_append_new(input,
		    json_pack("{s:s,s:o}", "role",
			strcmp(role, "developer") == 0 ||
				strcmp(role, "system") == 0
			    ? "developer"
			    : role,
			"content", converted));
		if (assistant &&
		    json_is_array(json_object_get(message, "tool_calls"))) {
			json_t *calls;
			json_t *call;
			size_t	call_index;

			calls = json_object_get(message, "tool_calls");
			json_array_foreach(calls, call_index, call)
			{
				json_t	   *function;
				const char *call_id;
				const char *name;
				const char *arguments;

				function = json_object_get(call, "function");
				call_id = json_string_value(
				    json_object_get(call, "id"));
				name = json_string_value(
				    json_object_get(function, "name"));
				arguments = json_string_value(
				    json_object_get(function, "arguments"));
				if (call_id != NULL && name != NULL)
					json_array_append_new(input,
					    json_pack("{s:s,s:s,s:s,s:s}",
						"type", "function_call",
						"call_id", call_id, "name",
						name, "arguments",
						arguments == NULL ? "{}"
								  : arguments));
			}
		}
	}
	result = json_pack("{s:o}", "input", input);
	json_object_set(result, "model", json_object_get(chat, "model"));
	if (json_is_boolean(json_object_get(chat, "stream")))
		json_object_set(result, "stream",
		    json_object_get(chat, "stream"));
	if (json_is_integer(json_object_get(chat, "max_completion_tokens")))
		json_object_set(result, "max_output_tokens",
		    json_object_get(chat, "max_completion_tokens"));
	else if (json_is_integer(json_object_get(chat, "max_tokens")))
		json_object_set(result, "max_output_tokens",
		    json_object_get(chat, "max_tokens"));
	if (json_is_real(json_object_get(chat, "temperature")) ||
	    json_is_integer(json_object_get(chat, "temperature")))
		json_object_set(result, "temperature",
		    json_object_get(chat, "temperature"));
	if (json_is_real(json_object_get(chat, "top_p")) ||
	    json_is_integer(json_object_get(chat, "top_p")))
		json_object_set(result, "top_p",
		    json_object_get(chat, "top_p"));
	if (json_is_string(json_object_get(chat, "stop")) ||
	    json_is_array(json_object_get(chat, "stop")))
		json_object_set(result, "stop", json_object_get(chat, "stop"));
	if (json_is_boolean(json_object_get(chat, "parallel_tool_calls")))
		json_object_set(result, "parallel_tool_calls",
		    json_object_get(chat, "parallel_tool_calls"));
	if (json_is_string(json_object_get(chat, "reasoning_effort")))
		json_object_set_new(result, "reasoning",
		    json_pack("{s:O}", "effort",
			json_object_get(chat, "reasoning_effort")));
	if (json_is_string(json_object_get(chat, "verbosity")))
		json_object_set(result, "verbosity",
		    json_object_get(chat, "verbosity"));
	if (json_is_object(json_object_get(chat, "response_format")))
		json_object_set(result, "response_format",
		    json_object_get(chat, "response_format"));
	tool_choice = json_object_get(chat, "tool_choice");
	if (json_is_string(tool_choice))
		json_object_set(result, "tool_choice", tool_choice);
	else if (json_is_object(tool_choice)) {
		json_t	   *function;
		const char *name;

		function = json_object_get(tool_choice, "function");
		name = json_string_value(json_object_get(function, "name"));
		if (json_is_object(function) && name != NULL)
			json_object_set_new(result, "tool_choice",
			    json_pack("{s:s,s:s}", "type", "function", "name",
				name));
	}
	if (json_object_get(result, "tool_choice") == NULL) {
		tool_choice = json_object_get(chat, "function_call");
		if (json_is_string(tool_choice))
			json_object_set(result, "tool_choice", tool_choice);
		else if (json_is_object(tool_choice) &&
		    json_is_string(json_object_get(tool_choice, "name")))
			json_object_set_new(result, "tool_choice",
			    json_pack("{s:s,s:s}", "type", "function", "name",
				json_string_value(
				    json_object_get(tool_choice, "name"))));
	}
	tools = json_object_get(chat, "tools");
	legacy_functions = json_object_get(chat, "functions");
	if (json_is_array(tools) || json_is_array(legacy_functions)) {
		json_t *tool;
		size_t	tool_index;

		if (!json_is_array(tools))
			tools = legacy_functions;
		response_tools = json_array();
		json_array_foreach(tools, tool_index, tool)
		{
			json_t *converted;

			converted = chat_function_to_response(
			    json_is_array(json_object_get(chat, "tools"))
				? json_object_get(tool, "function")
				: tool);
			if (converted != NULL)
				json_array_append_new(response_tools,
				    converted);
		}
		json_object_set_new(result, "tools", response_tools);
	}
	return result;
}

/*
** Translate a completed Responses object into one Chat Completions response.
**
** Text parts are concatenated in upstream output order.  Function calls become
** Chat tool_calls, and available token details are copied into their matching
** Chat usage fields.  The caller owns the returned JSON reference.
*/
json_t *
json_response_to_chat(json_t *response, json_t *request, char *error,
    size_t length)
{
	json_t *output;
	json_t *item;
	json_t *content;
	json_t *part;
	json_t *message;
	json_t *tool_calls;
	json_t *choice;
	json_t *choices;
	json_t *result;
	char   *text;
	int	has_tool_calls;
	size_t	index;
	size_t	part_index;

	/* Collapse completed Responses output into the one Chat Completions choice. */
	if (!json_is_object(response)) {
		set_error(error, length, "upstream response is malformed");
		return NULL;
	}
	text = oaio_strdup("");
	if (text == NULL)
		return NULL;
	has_tool_calls = 0;
	tool_calls = json_array();
	output = json_object_get(response, "output");
	if (json_is_array(output)) {
		json_array_foreach(output, index, item)
		{
			const char *item_type;

			item_type = json_string_value(
			    json_object_get(item, "type"));
			if (item_type != NULL &&
			    strcmp(item_type, "function_call") == 0) {
				const char *call_id;
				const char *name;
				const char *arguments;

				call_id = json_string_value(
				    json_object_get(item, "call_id"));
				name = json_string_value(
				    json_object_get(item, "name"));
				arguments = json_string_value(
				    json_object_get(item, "arguments"));
				if (call_id != NULL && name != NULL) {
					json_array_append_new(tool_calls,
					    json_pack("{s:s,s:s,s:{s:s,s:s}}",
						"id", call_id, "type",
						"function", "function", "name",
						name, "arguments",
						arguments == NULL ? "{}"
								  : arguments));
					has_tool_calls = 1;
				}
			}
			content = json_object_get(item, "content");
			if (!json_is_array(content))
				continue;
			json_array_foreach(content, part_index, part)
			{
				const char *part_type;

				part_type = json_string_value(
				    json_object_get(part, "type"));
				if (part_type != NULL &&
				    strcmp(part_type, "output_text") == 0 &&
				    json_is_string(
					json_object_get(part, "text"))) {
					char  *next;
					size_t old_len;
					size_t add_len;

					old_len = strlen(text);
					add_len = strlen(json_string_value(
					    json_object_get(part, "text")));
					next = realloc(text,
					    old_len + add_len + 1);
					if (next == NULL) {
						free(text);
						return NULL;
					}
					text = next;
					memcpy(text + old_len,
					    json_string_value(
						json_object_get(part, "text")),
					    add_len + 1);
				}
			}
		}
	}
	message = json_pack("{s:s,s:s}", "role", "assistant", "content", text);
	free(text);
	if (has_tool_calls)
		json_object_set_new(message, "tool_calls", tool_calls);
	else
		json_decref(tool_calls);
	choice = json_pack("{s:i,s:o,s:s}", "index", 0, "message", message,
	    "finish_reason", has_tool_calls ? "tool_calls" : "stop");
	choices = json_pack("[o]", choice);
	result = json_pack("{s:s,s:s,s:i,s:s,s:o}", "id", "chatcmpl_local",
	    "object", "chat.completion", "created", 0, "model",
	    json_string_value(json_object_get(request, "model")) != NULL
		? json_string_value(json_object_get(request, "model"))
		: "",
	    "choices", choices);
	if (json_is_object(json_object_get(response, "usage"))) {
		json_t *details;
		json_t *usage;
		json_t *upstream_usage;

		upstream_usage = json_object_get(response, "usage");
		usage = json_pack("{s:I,s:I,s:I}", "prompt_tokens",
		    json_integer_value(
			json_object_get(upstream_usage, "input_tokens")),
		    "completion_tokens",
		    json_integer_value(
			json_object_get(upstream_usage, "output_tokens")),
		    "total_tokens",
		    json_integer_value(
			json_object_get(upstream_usage, "total_tokens")));
		details =
		    json_object_get(upstream_usage, "input_tokens_details");
		if (json_is_integer(json_object_get(details, "cached_tokens")))
			json_object_set_new(usage, "prompt_tokens_details",
			    json_pack("{s:O}", "cached_tokens",
				json_object_get(details, "cached_tokens")));
		details =
		    json_object_get(upstream_usage, "output_tokens_details");
		if (json_is_integer(
			json_object_get(details, "reasoning_tokens")))
			json_object_set_new(usage, "completion_tokens_details",
			    json_pack("{s:O}", "reasoning_tokens",
				json_object_get(details, "reasoning_tokens")));
		json_object_set_new(result, "usage", usage);
	}
	return result;
}
