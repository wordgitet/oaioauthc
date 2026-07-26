/*
** Image request normalization interface.
**
** Both public functions borrow their request bytes and return an owned compact
** Codex JSON request in output.  IMAGE_RESULT_INVALID is a client-visible
** compatibility/syntax failure; IMAGE_RESULT_NOMEM is the only server failure
** they report.  Callers must free output only after IMAGE_RESULT_OK.
*/

#ifndef OAIOAUTHC_IMAGES_H
#define OAIOAUTHC_IMAGES_H

#include <stddef.h>

/* Codex OAuth compatibility and bounded-parser limits for image editing. */
#define IMAGE_MAX_REFERENCE_IMAGES 5
#define IMAGE_MAX_REFERENCE_BYTES ((size_t)50 * 1024 * 1024)
#define IMAGE_MAX_EDIT_BODY ((size_t)256 * 1024 * 1024)

enum image_result {
	IMAGE_RESULT_NOMEM = -1,
	IMAGE_RESULT_OK = 0,
	IMAGE_RESULT_INVALID = 1
};

/* Normalize a JSON image generation request to the supported Codex subset. */
int	image_prepare_generation(const void *, size_t, char **, char *,
	    size_t);
/* Parse and normalize multipart image editing into JSON data URLs. */
int	image_prepare_edit(const char *, const void *, size_t, char **, char *,
	    size_t);

#endif
