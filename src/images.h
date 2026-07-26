#ifndef OAIOAUTHC_IMAGES_H
#define OAIOAUTHC_IMAGES_H

#include <stddef.h>

#define IMAGE_MAX_REFERENCE_IMAGES 5
#define IMAGE_MAX_REFERENCE_BYTES ((size_t)50 * 1024 * 1024)
#define IMAGE_MAX_EDIT_BODY ((size_t)256 * 1024 * 1024)

enum image_result {
	IMAGE_RESULT_NOMEM = -1,
	IMAGE_RESULT_OK = 0,
	IMAGE_RESULT_INVALID = 1
};

int	image_prepare_generation(const void *, size_t, char **, char *,
	    size_t);
int	image_prepare_edit(const char *, const void *, size_t, char **, char *,
	    size_t);

#endif
