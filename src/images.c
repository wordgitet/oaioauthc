/*
** OpenAI image request validation and translation for the Codex backend.
**
** OpenAI-compatible image generation is JSON, but image editing uploads a
** multipart/form-data body.  Codex expects normalized JSON in both cases.
** Generation therefore keeps only the supported JSON fields.  Editing parses
** the multipart envelope, validates each field and file, then represents the
** accepted image bytes as data URLs in the outbound JSON request.
**
** Multipart input is untrusted binary data.  Parser helpers carry explicit
** lengths, cap headers, parts, complete request size, individual image size,
** and image count, and never rely on a terminator in uploaded content.  The
** conversion rejects unsupported features rather than silently changing their
** meaning, because an apparently successful image edit with altered options
** would be worse than a clear compatibility error.
*/

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "images.h"
#include "json.h"
#include "util.h"

#define MAX_BOUNDARY_LENGTH 70
#define MAX_FORM_HEADERS    (16 * 1024)
#define MAX_FORM_PARTS	    64

/*
** A non-owning view of a scalar multipart part.
**
** data points into the original request body.  present distinguishes an
** omitted field from an empty one, while is_file prevents file bytes from
** accidentally being interpreted as a textual option.
*/
struct form_field {
	const unsigned char *data;
	size_t		     length;
	int		     present;
	int		     is_file;
};

/*
** One accepted upload.  data remains a non-owning body slice; filename and
** content_type are duplicated because multipart header storage is temporary.
*/
struct image_file {
	const unsigned char *data;
	size_t		     length;
	char		    *filename;
	char		    *content_type;
};

/* A bounded ordered collection of accepted image uploads. */
struct image_list {
	struct image_file files[IMAGE_MAX_REFERENCE_IMAGES];
	size_t		  count;
};

/*
** Normalized multipart fields collected before validation and JSON emission.
**
** image_count counts every image part, including parts beyond the storage
** limit, so validation can report an excessive request instead of silently
** dropping uploads.  unsupported records the first incompatible option.
*/
struct image_form {
	struct form_field stream;
	struct form_field prompt;
	struct form_field model;
	struct form_field response_format;
	struct form_field n;
	struct form_field background;
	struct form_field quality;
	struct form_field size;
	struct image_list image;
	struct image_list image_array;
	size_t		  image_count;
	const char	 *unsupported;
	int		  has_mask;
};

/*
** Owned header metadata for the part currently being parsed.
**
** name, filename, and content_type are freed immediately after collect_part
** either copies/moves them into image_form or records the part as invalid.
*/
struct part_info {
	char *name;
	char *filename;
	char *content_type;
	int   has_filename;
};

/* OpenAI options that cannot be represented through the Codex OAuth API. */
static const char *unsupported_options[] = { "input_fidelity", "moderation",
	"output_compression", "output_format", "partial_images" };

/* Format a caller-owned diagnostic buffer without allocation. */
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

/* Copy a binary slice and append a NUL for header parsing. */
static char *
copy_bytes(const void *data, size_t length)
{
	char *copy;

	if (length == (size_t)-1)
		return NULL;
	copy = malloc(length + 1);
	if (copy == NULL)
		return NULL;
	memcpy(copy, data, length);
	copy[length] = '\0';
	return copy;
}

/* Find a byte sequence in binary input without using NUL-terminated APIs. */
static const unsigned char *
find_bytes(const unsigned char *data, size_t length,
    const unsigned char *needle, size_t needle_length)
{
	size_t offset;

	if (needle_length == 0)
		return data;
	if (needle_length > length)
		return NULL;
	for (offset = 0; offset <= length - needle_length; offset++) {
		if (data[offset] == needle[0] &&
		    memcmp(data + offset, needle, needle_length) == 0)
			return data + offset;
	}
	return NULL;
}

/* RFC token predicate for multipart parameter names and header field names. */
static int
ascii_token_char(unsigned char character)
{
	if (character == '\0')
		return 0;
	if (isalnum(character))
		return 1;
	return strchr("!#$%&'*+-.^_`|~", character) != NULL;
}

/* Restrict multipart boundaries to their permitted printable characters. */
static int
boundary_char(unsigned char character)
{
	if (isalnum(character))
		return 1;
	return strchr("'()+_,-./:=? ", character) != NULL;
}

/* Advance over HTTP optional whitespace in a C-string header value. */
static void
skip_space(const char **cursor)
{
	while (**cursor == ' ' || **cursor == '\t')
		(*cursor)++;
}

/*
** Parse one multipart parameter value, including quoted-pair escapes.
**
** Allocation failure and malformed syntax are distinct result values so the
** caller can return either an internal error or an invalid-request response.
*/
static int
read_parameter_value(const char **cursor, char **value)
{
	struct buffer buffer;
	const char   *start;
	const char   *end;

	*value = NULL;
	skip_space(cursor);
	if (**cursor == '"') {
		(*cursor)++;
		buffer_init(&buffer);
		while (**cursor != '\0' && **cursor != '"') {
			if (**cursor == '\r' || **cursor == '\n')
				goto invalid_quoted;
			if (**cursor == '\\') {
				(*cursor)++;
				if (**cursor == '\0')
					goto invalid_quoted;
			}
			if (buffer_append(&buffer, *cursor, 1) == -1) {
				buffer_free(&buffer);
				return IMAGE_RESULT_NOMEM;
			}
			(*cursor)++;
		}
		if (**cursor != '"')
			goto invalid_quoted;
		(*cursor)++;
		skip_space(cursor);
		if (**cursor != '\0' && **cursor != ';')
			goto invalid_quoted;
		*value = buffer_steal(&buffer);
		return *value == NULL ? IMAGE_RESULT_NOMEM : IMAGE_RESULT_OK;

	invalid_quoted:
		buffer_free(&buffer);
		return IMAGE_RESULT_INVALID;
	}
	start = *cursor;
	while (**cursor != '\0' && **cursor != ';')
		(*cursor)++;
	end = *cursor;
	while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	if (end == start)
		return IMAGE_RESULT_INVALID;
	*value = copy_bytes(start, (size_t)(end - start));
	return *value == NULL ? IMAGE_RESULT_NOMEM : IMAGE_RESULT_OK;
}

/*
** Extract the single valid boundary from a multipart Content-Type value.
**
** The returned boundary is owned by the caller and excludes the leading "--"
** used in body delimiters.  Duplicates, empty values, and unsafe characters
** are rejected before searching the uploaded byte stream.
*/
static int
parse_boundary(const char *content_type, char **boundary)
{
	const char *cursor;
	const char *start;
	const char *end;
	char	   *key;
	char	   *value;
	size_t	    index;
	size_t	    length;
	int	    result;

	*boundary = NULL;
	if (content_type == NULL)
		return IMAGE_RESULT_INVALID;
	cursor = content_type;
	skip_space(&cursor);
	start = cursor;
	while (*cursor != '\0' && *cursor != ';')
		cursor++;
	end = cursor;
	while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	if ((size_t)(end - start) != sizeof("multipart/form-data") - 1 ||
	    strncasecmp(start, "multipart/form-data",
		sizeof("multipart/form-data") - 1) != 0)
		return IMAGE_RESULT_INVALID;
	while (*cursor != '\0') {
		cursor++;
		skip_space(&cursor);
		start = cursor;
		while (ascii_token_char((unsigned char)*cursor))
			cursor++;
		end = cursor;
		if (end == start)
			return IMAGE_RESULT_INVALID;
		skip_space(&cursor);
		if (*cursor != '=')
			return IMAGE_RESULT_INVALID;
		cursor++;
		key = copy_bytes(start, (size_t)(end - start));
		if (key == NULL)
			return IMAGE_RESULT_NOMEM;
		value = NULL;
		result = read_parameter_value(&cursor, &value);
		if (result != IMAGE_RESULT_OK)
			goto parameter_done;
		if (strcasecmp(key, "boundary") == 0) {
			if (*boundary != NULL) {
				free(*boundary);
				*boundary = NULL;
				result = IMAGE_RESULT_INVALID;
				goto parameter_done;
			}
			*boundary = value;
			value = NULL;
		}
	parameter_done:
		free(value);
		free(key);
	}
	if (*boundary == NULL)
		return IMAGE_RESULT_INVALID;
	length = strlen(*boundary);
	if (length == 0 || length > MAX_BOUNDARY_LENGTH ||
	    (*boundary)[length - 1] == ' ')
		goto invalid;
	for (index = 0; index < length; index++) {
		if (!boundary_char((unsigned char)(*boundary)[index]))
			goto invalid;
	}
	return IMAGE_RESULT_OK;

invalid:
	free(*boundary);
	*boundary = NULL;
	return IMAGE_RESULT_INVALID;
}

/*
** Parse Content-Disposition metadata for one part.
**
** Multipart fields require a name.  Repeated name and filename parameters are
** invalid, rather than depending on a parser-specific first/last value rule.
*/
static int
parse_disposition(const char *value, struct part_info *part)
{
	const char *cursor;
	const char *start;
	const char *end;
	char	   *key;
	char	   *parameter;
	int	    result;

	cursor = value;
	skip_space(&cursor);
	start = cursor;
	while (*cursor != '\0' && *cursor != ';')
		cursor++;
	end = cursor;
	while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	if ((size_t)(end - start) != sizeof("form-data") - 1 ||
	    strncasecmp(start, "form-data", sizeof("form-data") - 1) != 0)
		return IMAGE_RESULT_INVALID;
	while (*cursor != '\0') {
		cursor++;
		skip_space(&cursor);
		start = cursor;
		while (ascii_token_char((unsigned char)*cursor))
			cursor++;
		end = cursor;
		if (end == start)
			return IMAGE_RESULT_INVALID;
		skip_space(&cursor);
		if (*cursor != '=')
			return IMAGE_RESULT_INVALID;
		cursor++;
		key = copy_bytes(start, (size_t)(end - start));
		if (key == NULL)
			return IMAGE_RESULT_NOMEM;
		parameter = NULL;
		result = read_parameter_value(&cursor, &parameter);
		if (result != IMAGE_RESULT_OK)
			goto parameter_done;
		if (strcasecmp(key, "name") == 0) {
			if (part->name != NULL) {
				result = IMAGE_RESULT_INVALID;
				goto parameter_done;
			}
			part->name = parameter;
			parameter = NULL;
		} else if (strcasecmp(key, "filename") == 0) {
			if (part->has_filename) {
				result = IMAGE_RESULT_INVALID;
				goto parameter_done;
			}
			part->filename = parameter;
			part->has_filename = 1;
			parameter = NULL;
		}
	parameter_done:
		free(parameter);
		free(key);
		if (result != IMAGE_RESULT_OK)
			return result;
	}
	return part->name == NULL ? IMAGE_RESULT_INVALID : IMAGE_RESULT_OK;
}

/* Release the owned header metadata for one multipart part. */
static void
part_info_free(struct part_info *part)
{
	free(part->name);
	free(part->filename);
	free(part->content_type);
	memset(part, 0, sizeof(*part));
}

/*
** Parse the bounded header section of one multipart part.
**
** The original body is immutable binary input, so headers are copied before
** line tokenization.  Only Content-Disposition and Content-Type are retained.
*/
static int
parse_part_headers(const unsigned char *data, size_t length,
    struct part_info *part)
{
	char *headers;
	char *cursor;
	char *line_end;
	char *colon;
	char *value;
	char *value_end;
	int   result;
	int   has_disposition;
	int   last_line;

	memset(part, 0, sizeof(*part));
	if (length == 0 || length > MAX_FORM_HEADERS ||
	    memchr(data, '\0', length) != NULL)
		return IMAGE_RESULT_INVALID;
	headers = copy_bytes(data, length);
	if (headers == NULL)
		return IMAGE_RESULT_NOMEM;
	has_disposition = 0;
	result = IMAGE_RESULT_OK;
	cursor = headers;
	while (*cursor != '\0') {
		line_end = strstr(cursor, "\r\n");
		if (line_end == NULL) {
			line_end = cursor + strlen(cursor);
			last_line = 1;
		} else {
			last_line = 0;
			*line_end = '\0';
		}
		colon = strchr(cursor, ':');
		if (colon == NULL || colon == cursor) {
			result = IMAGE_RESULT_INVALID;
			break;
		}
		*colon = '\0';
		for (value = cursor; *value != '\0'; value++) {
			if (!ascii_token_char((unsigned char)*value)) {
				result = IMAGE_RESULT_INVALID;
				break;
			}
		}
		if (result != IMAGE_RESULT_OK)
			break;
		value = colon + 1;
		while (*value == ' ' || *value == '\t')
			value++;
		value_end = value + strlen(value);
		while (value_end > value &&
		    (value_end[-1] == ' ' || value_end[-1] == '\t'))
			*--value_end = '\0';
		if (strcasecmp(cursor, "Content-Disposition") == 0) {
			if (has_disposition) {
				result = IMAGE_RESULT_INVALID;
				break;
			}
			has_disposition = 1;
			result = parse_disposition(value, part);
			if (result != IMAGE_RESULT_OK)
				break;
		} else if (strcasecmp(cursor, "Content-Type") == 0) {
			if (part->content_type != NULL || *value == '\0') {
				result = IMAGE_RESULT_INVALID;
				break;
			}
			part->content_type = copy_bytes(value, strlen(value));
			if (part->content_type == NULL) {
				result = IMAGE_RESULT_NOMEM;
				break;
			}
		}
		if (last_line)
			break;
		cursor = line_end + 2;
	}
	free(headers);
	if (result == IMAGE_RESULT_OK && !has_disposition)
		result = IMAGE_RESULT_INVALID;
	if (result != IMAGE_RESULT_OK)
		part_info_free(part);
	return result;
}

/* Store the first scalar field occurrence as a non-owning body view. */
static void
set_form_field(struct form_field *field, const struct part_info *part,
    const unsigned char *data, size_t length)
{
	if (field->present)
		return;
	field->data = data;
	field->length = length;
	field->present = 1;
	field->is_file = part->has_filename;
}

/* Check name against options intentionally unsupported by Codex. */
static int
is_unsupported(const char *name, const char **option)
{
	size_t index;

	for (index = 0; index <
	    sizeof(unsupported_options) / sizeof(unsupported_options[0]);
	    index++) {
		if (strcmp(name, unsupported_options[index]) == 0) {
			*option = unsupported_options[index];
			return 1;
		}
	}
	return 0;
}

/* Release copied filename/media-type metadata for image slices. */
static void
image_list_free(struct image_list *list)
{
	size_t index;

	for (index = 0; index < list->count; index++) {
		free(list->files[index].filename);
		free(list->files[index].content_type);
	}
	memset(list, 0, sizeof(*list));
}

/* Release all metadata accumulated during multipart parsing. */
static void
image_form_free(struct image_form *form)
{
	image_list_free(&form->image);
	image_list_free(&form->image_array);
	memset(form, 0, sizeof(*form));
}

/*
** Admit one image body slice into its ordered destination list.
**
** image_count records every supplied upload before the fixed storage limit is
** checked.  validate_form can then reject an excessive request instead of
** silently dropping images.  Filename and type ownership move from part.
*/
static int
add_image(struct image_form *form, struct image_list *list,
    struct part_info *part, const unsigned char *data, size_t length)
{
	struct image_file *file;

	form->image_count++;
	if (form->image_count > IMAGE_MAX_REFERENCE_IMAGES)
		return IMAGE_RESULT_OK;
	file = &list->files[list->count++];
	file->data = data;
	file->length = length;
	file->filename = part->filename;
	part->filename = NULL;
	if (part->content_type == NULL)
		part->content_type =
		    copy_bytes("image/png", sizeof("image/png") - 1);
	if (part->content_type == NULL)
		return IMAGE_RESULT_NOMEM;
	file->content_type = part->content_type;
	part->content_type = NULL;
	return IMAGE_RESULT_OK;
}

/* Classify a parsed part as scalar metadata, image, or incompatible input. */
static int
collect_part(struct image_form *form, struct part_info *part,
    const unsigned char *data, size_t length)
{
	const char *unsupported;

	if (strcmp(part->name, "stream") == 0)
		set_form_field(&form->stream, part, data, length);
	else if (strcmp(part->name, "prompt") == 0)
		set_form_field(&form->prompt, part, data, length);
	else if (strcmp(part->name, "model") == 0)
		set_form_field(&form->model, part, data, length);
	else if (strcmp(part->name, "response_format") == 0)
		set_form_field(&form->response_format, part, data, length);
	else if (strcmp(part->name, "n") == 0)
		set_form_field(&form->n, part, data, length);
	else if (strcmp(part->name, "background") == 0)
		set_form_field(&form->background, part, data, length);
	else if (strcmp(part->name, "quality") == 0)
		set_form_field(&form->quality, part, data, length);
	else if (strcmp(part->name, "size") == 0)
		set_form_field(&form->size, part, data, length);
	else if (strcmp(part->name, "mask") == 0)
		form->has_mask = 1;
	else if (is_unsupported(part->name, &unsupported) &&
	    form->unsupported == NULL)
		form->unsupported = unsupported;
	else if (part->has_filename && strcmp(part->name, "image") == 0)
		return add_image(form, &form->image, part, data, length);
	else if (part->has_filename && strcmp(part->name, "image[]") == 0)
		return add_image(form, &form->image_array, part, data, length);
	return IMAGE_RESULT_OK;
}

/*
** Find the next CRLF-prefixed delimiter that is a legal multipart boundary.
**
** Matching the suffix prevents arbitrary image bytes containing the boundary
** string from terminating a part unless the complete framing is present.
*/
static const unsigned char *
next_boundary(const unsigned char *data, size_t length,
    const unsigned char *delimiter, size_t delimiter_length)
{
	const unsigned char *candidate;
	size_t		     remaining;

	while ((candidate = find_bytes(data, length,
		    (const unsigned char *)"\r\n", 2)) != NULL) {
		remaining = length - (size_t)(candidate - data);
		if (remaining >= delimiter_length + 4 &&
		    memcmp(candidate + 2, delimiter, delimiter_length) == 0 &&
		    (memcmp(candidate + 2 + delimiter_length, "--", 2) == 0 ||
			memcmp(candidate + 2 + delimiter_length, "\r\n", 2) ==
			    0))
			return candidate;
		candidate += 2;
		length = remaining - 2;
		data = candidate;
	}
	return NULL;
}

/*
** Parse an entire multipart/form-data body into form.
**
** All body references in form are non-owning slices.  Cursor arithmetic is
** bounded by length, part count is capped, and metadata is released on every
** failure.  A successful form remains valid until the caller releases body.
*/
static int
parse_multipart(const char *content_type, const void *body, size_t length,
    struct image_form *form)
{
	struct buffer	     marker;
	struct part_info     part;
	const unsigned char *data;
	const unsigned char *cursor;
	const unsigned char *header_end;
	const unsigned char *boundary_at;
	char		    *boundary;
	size_t		     remaining;
	size_t		     part_count;
	int		     result;

	/*
	 * Keep pointers into the original body until normalization is complete.
	 * Bounds are checked before every delimiter search so binary image content
	 * cannot turn into an unbounded string scan.
	 */
	memset(form, 0, sizeof(*form));
	buffer_init(&marker);
	memset(&part, 0, sizeof(part));
	boundary = NULL;
	result = parse_boundary(content_type, &boundary);
	if (result != IMAGE_RESULT_OK)
		goto multipart_done;
	if (buffer_append_string(&marker, "--") == -1 ||
	    buffer_append_string(&marker, boundary) == -1) {
		result = IMAGE_RESULT_NOMEM;
		goto multipart_done;
	}
	free(boundary);
	boundary = NULL;
	data = body;
	if (length < marker.len + 2 ||
	    memcmp(data, marker.data, marker.len) != 0 ||
	    memcmp(data + marker.len, "\r\n", 2) != 0) {
		result = IMAGE_RESULT_INVALID;
		goto multipart_done;
	}
	cursor = data + marker.len + 2;
	remaining = length - marker.len - 2;
	part_count = 0;
	for (;;) {
		if (++part_count > MAX_FORM_PARTS) {
			result = IMAGE_RESULT_INVALID;
			break;
		}
		header_end = find_bytes(cursor, remaining,
		    (const unsigned char *)"\r\n\r\n", 4);
		if (header_end == NULL) {
			result = IMAGE_RESULT_INVALID;
			break;
		}
		result = parse_part_headers(cursor,
		    (size_t)(header_end - cursor), &part);
		if (result != IMAGE_RESULT_OK)
			break;
		cursor = header_end + 4;
		remaining = length - (size_t)(cursor - data);
		boundary_at = next_boundary(cursor, remaining,
		    (const unsigned char *)marker.data, marker.len);
		if (boundary_at == NULL) {
			result = IMAGE_RESULT_INVALID;
			break;
		}
		result = collect_part(form, &part, cursor,
		    (size_t)(boundary_at - cursor));
		part_info_free(&part);
		if (result != IMAGE_RESULT_OK)
			break;
		cursor = boundary_at + 2 + marker.len;
		remaining = length - (size_t)(cursor - data);
		if (remaining >= 2 && memcmp(cursor, "--", 2) == 0) {
			remaining -= 2;
			if (remaining >= 2 &&
			    memcmp(cursor + 2, "\r\n", 2) == 0)
				remaining -= 2;
			result = remaining == 0 ? IMAGE_RESULT_OK
						: IMAGE_RESULT_INVALID;
			break;
		}
		if (remaining < 2 || memcmp(cursor, "\r\n", 2) != 0) {
			result = IMAGE_RESULT_INVALID;
			break;
		}
		cursor += 2;
		remaining -= 2;
	}
multipart_done:
	free(boundary);
	buffer_free(&marker);
	part_info_free(&part);
	if (result != IMAGE_RESULT_OK)
		image_form_free(form);
	return result;
}

/* Compare a scalar field without interpreting an uploaded file as text. */
static int
field_equals(const struct form_field *field, const char *value)
{
	size_t length;

	if (!field->present || field->is_file)
		return 0;
	length = strlen(value);
	return field->length == length &&
	    memcmp(field->data, value, length) == 0;
}

/* Copy one scalar multipart field into a JSON string property. */
static int
set_json_field(json_t *object, const char *name, const struct form_field *field)
{
	json_t *value;

	value = json_stringn((const char *)field->data, field->length);
	if (value == NULL)
		return -1;
	if (json_object_set(object, name, value) == -1) {
		json_decref(value);
		return -1;
	}
	json_decref(value);
	return 0;
}

/*
** Parse optional n into an exact JSON integer when possible, otherwise a real.
**
** Invalid numeric text is ignored for compatibility, leaving the upstream
** default in effect.  Allocation failure is still reported to the caller.
*/
static int
set_json_number(json_t *object, const struct form_field *field)
{
	char	  *text;
	char	  *cursor;
	char	  *end;
	double	   number;
	json_int_t integer;
	json_t	  *value;
	int	   valid;

	if (!field->present || field->is_file || field->length == 0)
		return 0;
	text = copy_bytes(field->data, field->length);
	if (text == NULL)
		return -1;
	cursor = text;
	while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
	    *cursor == '\n')
		cursor++;
	valid = 1;
	if (*cursor == '\0') {
		number = 0;
		end = cursor;
	} else {
		errno = 0;
		number = strtod(cursor, &end);
		while (
		    *end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
			end++;
		if (errno != 0 || end == cursor || *end != '\0')
			valid = 0;
	}
	if (!valid || number > DBL_MAX || number < -DBL_MAX ||
	    number != number) {
		free(text);
		return 0;
	}
	if (number >= -9007199254740991.0 && number <= 9007199254740991.0) {
		integer = (json_int_t)number;
		if ((double)integer == number)
			value = json_integer(integer);
		else
			value = json_real(number);
	} else {
		value = json_real(number);
	}
	free(text);
	if (value == NULL)
		return -1;
	if (json_object_set(object, "n", value) == -1) {
		json_decref(value);
		return -1;
	}
	json_decref(value);
	return 0;
}

/*
** Convert an accepted upload to the JSON data URL required by Codex.
**
** EVP_EncodeBlock needs an int length, so size arithmetic is checked before
** conversion.  The caller owns the returned string.
*/
static char *
file_data_url(const struct image_file *file)
{
	struct buffer  url;
	unsigned char *encoded;
	size_t	       encoded_length;
	int	       result;

	if (file->length > (size_t)INT_MAX ||
	    file->length > ((size_t)-1 - 2) / 4 * 3)
		return NULL;
	encoded_length = 4 * ((file->length + 2) / 3);
	encoded = malloc(encoded_length + 1);
	if (encoded == NULL)
		return NULL;
	buffer_init(&url);
	result = EVP_EncodeBlock(encoded, file->data, (int)file->length);
	if (result < 0 || (size_t)result != encoded_length)
		goto data_url_done;
	encoded[encoded_length] = '\0';
	if (buffer_append_string(&url, "data:") == -1 ||
	    buffer_append_string(&url, file->content_type) == -1 ||
	    buffer_append_string(&url, ";base64,") == -1 ||
	    buffer_append(&url, encoded, encoded_length) == -1) {
		goto data_url_done;
	}
	free(encoded);
	return buffer_steal(&url);

data_url_done:
	free(encoded);
	buffer_free(&url);
	return NULL;
}

/* Append image_url objects in the same order as the multipart upload fields. */
static int
append_image_list(json_t *images, const struct image_list *list)
{
	json_t *entry;
	char   *url;
	size_t	index;

	for (index = 0; index < list->count; index++) {
		url = file_data_url(&list->files[index]);
		if (url == NULL)
			return -1;
		entry = json_pack("{s:s}", "image_url", url);
		free(url);
		if (entry == NULL || json_array_append(images, entry) == -1) {
			json_decref(entry);
			return -1;
		}
		json_decref(entry);
	}
	return 0;
}

/*
** Enforce semantic compatibility after syntax parsing succeeds.
**
** Parsing proves that the multipart body is well formed; this function decides
** whether its fields can be represented faithfully by the Codex image API.
*/
static int
validate_form(const struct image_form *form, char *error, size_t length)
{
	const struct image_file *file;
	size_t			 index;

	/* Reject incompatible options instead of silently changing image semantics. */
	if (field_equals(&form->stream, "true")) {
		set_error(error, length,
		    "Streaming image editing is not supported by ChatGPT OAuth.");
		return IMAGE_RESULT_INVALID;
	}
	if (form->has_mask) {
		set_error(error, length,
		    "Image masks are not supported by ChatGPT OAuth.");
		return IMAGE_RESULT_INVALID;
	}
	if (!form->prompt.present || form->prompt.is_file ||
	    form->prompt.length == 0) {
		set_error(error, length,
		    "`prompt` must be a non-empty string.");
		return IMAGE_RESULT_INVALID;
	}
	if (!form->model.present || form->model.is_file ||
	    form->model.length == 0) {
		set_error(error, length, "`model` must be a non-empty string.");
		return IMAGE_RESULT_INVALID;
	}
	if (form->image_count == 0) {
		set_error(error, length, "At least one `image` is required.");
		return IMAGE_RESULT_INVALID;
	}
	if (form->image_count > IMAGE_MAX_REFERENCE_IMAGES) {
		set_error(error, length,
		    "ChatGPT OAuth supports at most 5 reference images.");
		return IMAGE_RESULT_INVALID;
	}
	for (index = 0; index < form->image.count; index++) {
		file = &form->image.files[index];
		if (file->length > IMAGE_MAX_REFERENCE_BYTES)
			goto oversized;
	}
	for (index = 0; index < form->image_array.count; index++) {
		file = &form->image_array.files[index];
		if (file->length > IMAGE_MAX_REFERENCE_BYTES)
			goto oversized;
	}
	if (form->unsupported != NULL) {
		set_error(error, length,
		    "`%s` is not supported by ChatGPT OAuth image editing.",
		    form->unsupported);
		return IMAGE_RESULT_INVALID;
	}
	if (form->response_format.present &&
	    !field_equals(&form->response_format, "b64_json")) {
		set_error(error, length,
		    "ChatGPT OAuth image editing only returns `b64_json`.");
		return IMAGE_RESULT_INVALID;
	}
	return IMAGE_RESULT_OK;

oversized:
	set_error(error, length,
	    "Reference image `%s` exceeds the 50 MB limit.",
	    file->filename == NULL ? "" : file->filename);
	return IMAGE_RESULT_INVALID;
}

/*
** Validate an OpenAI-compatible generation object and produce Codex JSON.
**
** Only the supported field set is copied.  output is an owned compact JSON
** string on success.  Invalid input and allocation failure have distinct
** result codes so proxy.c can choose the correct HTTP status.
*/
int
image_prepare_generation(const void *body, size_t length, char **output,
    char *error, size_t error_length)
{
	static const char *allowed[] = { "background", "n", "quality", "size" };
	json_error_t	   json_error;
	json_t		  *root;
	json_t		  *normalized;
	json_t		  *value;
	size_t		   index;

	/* Emit only the Codex-supported subset; callers own output on success. */
	*output = NULL;
	root = json_loadb(body, length, 0, &json_error);
	if (root == NULL) {
		set_error(error, error_length,
		    "Image generation request is invalid JSON.");
		return IMAGE_RESULT_INVALID;
	}
	if (!json_is_object(root)) {
		json_decref(root);
		set_error(error, error_length,
		    "Image generation request body must be a JSON object.");
		return IMAGE_RESULT_INVALID;
	}
	if (json_is_true(json_object_get(root, "stream"))) {
		json_decref(root);
		set_error(error, error_length,
		    "Streaming image generation is not supported by ChatGPT OAuth.");
		return IMAGE_RESULT_INVALID;
	}
	value = json_object_get(root, "prompt");
	if (!json_is_string(value) || json_string_length(value) == 0) {
		json_decref(root);
		set_error(error, error_length,
		    "`prompt` must be a non-empty string.");
		return IMAGE_RESULT_INVALID;
	}
	value = json_object_get(root, "model");
	if (!json_is_string(value) || json_string_length(value) == 0) {
		json_decref(root);
		set_error(error, error_length,
		    "`model` must be a non-empty string.");
		return IMAGE_RESULT_INVALID;
	}
	for (index = 0; index <
	    sizeof(unsupported_options) / sizeof(unsupported_options[0]);
	    index++) {
		if (json_object_get(root, unsupported_options[index]) != NULL) {
			set_error(error, error_length,
			    "`%s` is not supported by ChatGPT OAuth image generation.",
			    unsupported_options[index]);
			json_decref(root);
			return IMAGE_RESULT_INVALID;
		}
	}
	value = json_object_get(root, "response_format");
	if (value != NULL &&
	    (!json_is_string(value) ||
		strcmp(json_string_value(value), "b64_json") != 0)) {
		json_decref(root);
		set_error(error, error_length,
		    "ChatGPT OAuth image generation only returns `b64_json`.");
		return IMAGE_RESULT_INVALID;
	}
	normalized = json_object();
	if (normalized == NULL ||
	    json_object_set(normalized, "model",
		json_object_get(root, "model")) == -1 ||
	    json_object_set(normalized, "prompt",
		json_object_get(root, "prompt")) == -1)
		goto nomem;
	for (index = 0; index < sizeof(allowed) / sizeof(allowed[0]); index++) {
		value = json_object_get(root, allowed[index]);
		if (value != NULL &&
		    json_object_set(normalized, allowed[index], value) == -1)
			goto nomem;
	}
	*output = json_dump_compact(normalized);
	json_decref(normalized);
	json_decref(root);
	if (*output == NULL) {
		set_error(error, error_length, "out of memory");
		return IMAGE_RESULT_NOMEM;
	}
	return IMAGE_RESULT_OK;

nomem:
	json_decref(normalized);
	json_decref(root);
	set_error(error, error_length, "out of memory");
	return IMAGE_RESULT_NOMEM;
}

/*
** Translate a bounded multipart image edit into its Codex JSON request.
**
** Files are never written to disk: validated input bytes become data URLs in
** memory.  Temporary parser metadata is released on all exits; output belongs
** to the caller only when IMAGE_RESULT_OK is returned.
*/
int
image_prepare_edit(const char *content_type, const void *body, size_t length,
    char **output, char *error, size_t error_length)
{
	struct image_form form;
	json_t		 *root;
	json_t		 *images;
	int		  result;

	/* Convert uploaded bytes to JSON data URLs only after full form validation. */
	*output = NULL;
	if (length > IMAGE_MAX_EDIT_BODY) {
		set_error(error, error_length,
		    "Image editing request exceeds the 256 MB limit.");
		return IMAGE_RESULT_INVALID;
	}
	result = parse_multipart(content_type, body, length, &form);
	if (result != IMAGE_RESULT_OK) {
		set_error(error, error_length,
		    result == IMAGE_RESULT_NOMEM
			? "out of memory"
			: "Image editing request contains invalid form data.");
		return result;
	}
	result = validate_form(&form, error, error_length);
	if (result != IMAGE_RESULT_OK) {
		image_form_free(&form);
		return result;
	}
	root = json_object();
	images = json_array();
	if (root == NULL || images == NULL ||
	    append_image_list(images, &form.image) == -1 ||
	    append_image_list(images, &form.image_array) == -1 ||
	    json_object_set(root, "images", images) == -1)
		goto nomem;
	json_decref(images);
	images = NULL;
	if (set_json_field(root, "model", &form.model) == -1 ||
	    set_json_field(root, "prompt", &form.prompt) == -1 ||
	    set_json_number(root, &form.n) == -1)
		goto nomem;
	if (form.background.present && !form.background.is_file &&
	    form.background.length > 0 &&
	    set_json_field(root, "background", &form.background) == -1)
		goto nomem;
	if (form.quality.present && !form.quality.is_file &&
	    form.quality.length > 0 &&
	    set_json_field(root, "quality", &form.quality) == -1)
		goto nomem;
	if (form.size.present && !form.size.is_file && form.size.length > 0 &&
	    set_json_field(root, "size", &form.size) == -1)
		goto nomem;
	*output = json_dump_compact(root);
	json_decref(root);
	image_form_free(&form);
	if (*output == NULL) {
		set_error(error, error_length, "out of memory");
		return IMAGE_RESULT_NOMEM;
	}
	return IMAGE_RESULT_OK;

nomem:
	json_decref(images);
	json_decref(root);
	image_form_free(&form);
	set_error(error, error_length, "out of memory");
	return IMAGE_RESULT_NOMEM;
}
