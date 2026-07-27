/*
 * Multipart and JSON image-translation tests.  The local builder creates
 * exact form framing so malformed and boundary-sensitive cases stay explicit.
 */

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "images.h"
#include "test.h"
#include "util.h"

/*
** Exact multipart byte builder used to test the production parser.
**
** body may deliberately contain NUL and boundary-like bytes.  finished avoids
** accidentally creating a body with two closing delimiters in negative tests.
*/
struct multipart {
	struct buffer body;
	const char   *boundary;
	int	      finished;
};

/* Initialize a builder with a borrowed boundary string. */
static void
multipart_init(struct multipart *multipart, const char *boundary)
{
	buffer_init(&multipart->body);
	multipart->boundary = boundary;
	multipart->finished = 0;
}

/* Append one Content-Disposition/Content-Type header section. */
static int
multipart_header(struct multipart *multipart, const char *name,
    const char *filename, const char *content_type)
{
	if (buffer_append_string(&multipart->body, "--") == -1 ||
	    buffer_append_string(&multipart->body, multipart->boundary) == -1 ||
	    buffer_append_string(&multipart->body,
		"\r\nContent-Disposition: form-data; name=\"") == -1 ||
	    buffer_append_string(&multipart->body, name) == -1 ||
	    buffer_append_string(&multipart->body, "\"") == -1)
		return -1;
	if (filename != NULL &&
	    (buffer_append_string(&multipart->body, "; filename=\"") == -1 ||
		buffer_append_string(&multipart->body, filename) == -1 ||
		buffer_append_string(&multipart->body, "\"") == -1))
		return -1;
	if (content_type != NULL &&
	    (buffer_append_string(&multipart->body, "\r\nContent-Type: ") ==
		    -1 ||
		buffer_append_string(&multipart->body, content_type) == -1))
		return -1;
	return buffer_append_string(&multipart->body, "\r\n\r\n");
}

/* Append one textual form field with correct trailing CRLF framing. */
static int
multipart_field(struct multipart *multipart, const char *name,
    const char *value)
{
	if (multipart_header(multipart, name, NULL, NULL) == -1 ||
	    buffer_append_string(&multipart->body, value) == -1)
		return -1;
	return buffer_append_string(&multipart->body, "\r\n");
}

/* Append one binary upload without converting it through string APIs. */
static int
multipart_file(struct multipart *multipart, const char *name,
    const char *filename, const char *content_type, const void *data,
    size_t length)
{
	if (multipart_header(multipart, name, filename, content_type) == -1 ||
	    buffer_append(&multipart->body, data, length) == -1)
		return -1;
	return buffer_append_string(&multipart->body, "\r\n");
}

/* Close the body once; a second close indicates a malformed test fixture. */
static int
multipart_finish(struct multipart *multipart)
{
	if (multipart->finished)
		return -1;
	multipart->finished = 1;
	if (buffer_append_string(&multipart->body, "--") == -1 ||
	    buffer_append_string(&multipart->body, multipart->boundary) == -1)
		return -1;
	return buffer_append_string(&multipart->body, "--\r\n");
}

/* Validate generation normalization and each public compatibility rejection. */
static int
test_generation(void)
{
	static const char valid[] =
	    "{\"model\":\"image-model\",\"prompt\":\"draw a square\","
	    "\"background\":\"opaque\",\"n\":2,\"quality\":\"low\","
	    "\"size\":\"1024x1024\",\"response_format\":\"b64_json\","
	    "\"ignored\":\"value\",\"stream\":false}";
	static const char *unsupported[] = { "input_fidelity", "moderation",
		"output_compression", "output_format", "partial_images" };
	char		   input[256];
	char		   error[256];
	char		  *output;
	json_t		  *root;
	size_t		   index;
	int		   result;

	result = image_prepare_generation(valid, sizeof(valid) - 1, &output,
	    error, sizeof(error));
	CHECK(result == IMAGE_RESULT_OK);
	root = json_loads(output, 0, NULL);
	free(output);
	CHECK(json_is_object(root));
	CHECK(json_object_size(root) == 6);
	CHECK(strcmp(json_string_value(json_object_get(root, "model")),
		  "image-model") == 0);
	CHECK(strcmp(json_string_value(json_object_get(root, "prompt")),
		  "draw a square") == 0);
	CHECK(json_integer_value(json_object_get(root, "n")) == 2);
	CHECK(json_object_get(root, "ignored") == NULL);
	CHECK(json_object_get(root, "response_format") == NULL);
	CHECK(json_object_get(root, "stream") == NULL);
	json_decref(root);

	result =
	    image_prepare_generation("{", 1, &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "invalid JSON") != NULL);
	result =
	    image_prepare_generation("[]", 2, &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "JSON object") != NULL);
	result = image_prepare_generation(
	    "{\"model\":\"image-model\",\"prompt\":\"x\",\"stream\":true}",
	    sizeof("{\"model\":\"image-model\",\"prompt\":\"x\","
		   "\"stream\":true}") -
		1,
	    &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "Streaming") != NULL);
	result = image_prepare_generation("{\"prompt\":\"x\"}",
	    sizeof("{\"prompt\":\"x\"}") - 1, &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "`model`") != NULL);
	result = image_prepare_generation("{\"model\":\"\",\"prompt\":\"x\"}",
	    sizeof("{\"model\":\"\",\"prompt\":\"x\"}") - 1, &output, error,
	    sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	result = image_prepare_generation(
	    "{\"model\":\"image-model\",\"prompt\":\"\"}",
	    sizeof("{\"model\":\"image-model\",\"prompt\":\"\"}") - 1, &output,
	    error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	result = image_prepare_generation(
	    "{\"model\":\"image-model\",\"prompt\":\"x\","
	    "\"response_format\":\"url\"}",
	    sizeof("{\"model\":\"image-model\",\"prompt\":\"x\","
		   "\"response_format\":\"url\"}") -
		1,
	    &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	for (index = 0; index < sizeof(unsupported) / sizeof(unsupported[0]);
	    index++) {
		CHECK(snprintf(input, sizeof(input),
			  "{\"model\":\"image-model\",\"prompt\":\"x\","
			  "\"%s\":null}",
			  unsupported[index]) < (int)sizeof(input));
		result = image_prepare_generation(input, strlen(input), &output,
		    error, sizeof(error));
		CHECK(result == IMAGE_RESULT_INVALID);
		CHECK(strstr(error, unsupported[index]) != NULL);
	}
	return 0;
}

/* Verify image order, binary data URLs, and optional edit fields. */
static int
test_edit_success(void)
{
	static const unsigned char first[] = { 1, 2, 3 };
	static const unsigned char second[] = { 4, 5, 0, '\r', '\n', '-', '-',
		't', 'e', 's', 't', 'X', 6 };
	struct multipart	   multipart;
	char			   content_type[128];
	char			   error[256];
	char			  *output;
	json_t			  *root;
	json_t			  *images;
	json_t			  *entry;
	int			   result;

	multipart_init(&multipart, "test");
	CHECK(multipart_field(&multipart, "prompt", "combine them") == 0);
	CHECK(multipart_field(&multipart, "model", "image-model") == 0);
	CHECK(multipart_file(&multipart, "image[]", "second.webp", "image/webp",
		  second, sizeof(second)) == 0);
	CHECK(multipart_file(&multipart, "image", "first.png", "image/png",
		  first, sizeof(first)) == 0);
	CHECK(multipart_field(&multipart, "n", "2") == 0);
	CHECK(multipart_field(&multipart, "background", "opaque") == 0);
	CHECK(multipart_field(&multipart, "quality", "high") == 0);
	CHECK(multipart_field(&multipart, "size", "1024x1024") == 0);
	CHECK(multipart_field(&multipart, "response_format", "b64_json") == 0);
	CHECK(multipart_field(&multipart, "ignored", "value") == 0);
	CHECK(multipart_finish(&multipart) == 0);
	CHECK(snprintf(content_type, sizeof(content_type),
		  "Multipart/Form-Data; charset=utf-8; boundary=\"%s\"",
		  multipart.boundary) < (int)sizeof(content_type));
	result = image_prepare_edit(content_type, multipart.body.data,
	    multipart.body.len, &output, error, sizeof(error));
	buffer_free(&multipart.body);
	CHECK(result == IMAGE_RESULT_OK);
	root = json_loads(output, 0, NULL);
	free(output);
	CHECK(json_is_object(root));
	CHECK(json_object_size(root) == 7);
	CHECK(strcmp(json_string_value(json_object_get(root, "model")),
		  "image-model") == 0);
	CHECK(strcmp(json_string_value(json_object_get(root, "prompt")),
		  "combine them") == 0);
	CHECK(json_integer_value(json_object_get(root, "n")) == 2);
	images = json_object_get(root, "images");
	CHECK(json_array_size(images) == 2);
	entry = json_array_get(images, 0);
	CHECK(strcmp(json_string_value(json_object_get(entry, "image_url")),
		  "data:image/png;base64,AQID") == 0);
	entry = json_array_get(images, 1);
	CHECK(strncmp(json_string_value(json_object_get(entry, "image_url")),
		  "data:image/webp;base64,",
		  sizeof("data:image/webp;base64,") - 1) == 0);
	json_decref(root);
	return 0;
}

/* Build a valid edit, vary one condition, and require its error text. */
static int
expect_edit_error(const char *extra_name, const char *extra_value,
    int include_model, int include_image, const char *expected)
{
	static const unsigned char image[] = { 1, 2, 3 };
	struct multipart	   multipart;
	char			   error[256];
	char			  *output;
	int			   result;

	multipart_init(&multipart, "edge");
	if (include_model &&
	    multipart_field(&multipart, "model", "image-model") == -1)
		goto nomem;
	if (multipart_field(&multipart, "prompt", "edit") == -1)
		goto nomem;
	if (include_image &&
	    multipart_file(&multipart, "image", "input.png", "image/png", image,
		sizeof(image)) == -1)
		goto nomem;
	if (extra_name != NULL &&
	    multipart_field(&multipart, extra_name, extra_value) == -1)
		goto nomem;
	if (multipart_finish(&multipart) == -1)
		goto nomem;
	result = image_prepare_edit("multipart/form-data; boundary=edge",
	    multipart.body.data, multipart.body.len, &output, error,
	    sizeof(error));
	buffer_free(&multipart.body);
	if (result != IMAGE_RESULT_INVALID || strstr(error, expected) == NULL)
		return 1;
	return 0;

nomem:
	buffer_free(&multipart.body);
	return 1;
}

/* Exercise rejected options, missing fields, and malformed edit forms. */
static int
test_edit_errors(void)
{
	struct multipart multipart;
	char		 error[256];
	char		*output;
	int		 result;
	int		 index;

	CHECK(expect_edit_error(NULL, NULL, 0, 1, "`model`") == 0);
	CHECK(expect_edit_error(NULL, NULL, 1, 0, "At least one") == 0);
	CHECK(expect_edit_error("stream", "true", 1, 1, "Streaming") == 0);
	CHECK(expect_edit_error("mask", "mask", 1, 1, "masks") == 0);
	CHECK(expect_edit_error("output_format", "png", 1, 1,
		  "output_format") == 0);
	CHECK(expect_edit_error("response_format", "url", 1, 1,
		  "only returns") == 0);

	multipart_init(&multipart, "many");
	CHECK(multipart_field(&multipart, "model", "image-model") == 0);
	CHECK(multipart_field(&multipart, "prompt", "edit") == 0);
	for (index = 0; index < 6; index++)
		CHECK(multipart_file(&multipart, "image[]", "input.png",
			  "image/png", "x", 1) == 0);
	CHECK(multipart_finish(&multipart) == 0);
	result = image_prepare_edit("multipart/form-data; boundary=many",
	    multipart.body.data, multipart.body.len, &output, error,
	    sizeof(error));
	buffer_free(&multipart.body);
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "at most 5") != NULL);

	result = image_prepare_edit("application/json", "{}", 2, &output, error,
	    sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "invalid form data") != NULL);
	result = image_prepare_edit("multipart/form-data", "x", 1, &output,
	    error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	result = image_prepare_edit("multipart/form-data; boundary=broken",
	    "--broken\r\nContent-Disposition: form-data; name=\"model\"\r\n"
	    "\r\nimage-model\r\n",
	    sizeof("--broken\r\nContent-Disposition: "
		   "form-data; name=\"model\"\r\n\r\nimage-model\r\n") -
		1,
	    &output, error, sizeof(error));
	CHECK(result == IMAGE_RESULT_INVALID);
	return 0;
}

/* Confirm the edit-body size limit is rejected before multipart parsing. */
static int
test_oversized_edit(void)
{
	static const char header[] =
	    "--large\r\n"
	    "Content-Disposition: form-data; name=\"model\"\r\n\r\n"
	    "image-model\r\n"
	    "--large\r\n"
	    "Content-Disposition: form-data; name=\"prompt\"\r\n\r\n"
	    "edit\r\n"
	    "--large\r\n"
	    "Content-Disposition: form-data; name=\"image\"; "
	    "filename=\"large.png\"\r\n"
	    "Content-Type: image/png\r\n\r\n";
	static const char trailer[] = "\r\n--large--\r\n";
	char		 *body;
	char		  error[256];
	char		 *output;
	size_t		  image_length;
	size_t		  total;
	int		  result;

	image_length = IMAGE_MAX_REFERENCE_BYTES + 1;
	total = sizeof(header) - 1 + image_length + sizeof(trailer) - 1;
	body = malloc(total);
	CHECK(body != NULL);
	memcpy(body, header, sizeof(header) - 1);
	memset(body + sizeof(header) - 1, 0, image_length);
	memcpy(body + sizeof(header) - 1 + image_length, trailer,
	    sizeof(trailer) - 1);
	result = image_prepare_edit("multipart/form-data; boundary=large", body,
	    total, &output, error, sizeof(error));
	free(body);
	CHECK(result == IMAGE_RESULT_INVALID);
	CHECK(strstr(error, "large.png") != NULL);
	CHECK(strstr(error, "50 MB") != NULL);
	return 0;
}

/* Run all image compatibility groups so failures remain independently named. */
int
main(void)
{
	CHECK(test_generation() == 0);
	CHECK(test_edit_success() == 0);
	CHECK(test_edit_errors() == 0);
	CHECK(test_oversized_edit() == 0);
	return 0;
}
