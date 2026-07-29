/*
** Explicit cleansing helpers for project-owned secret material.
**
** OAuth credentials and local API keys are ordinary heap strings in the
** program.  OpenSSL_cleanse prevents an optimizing compiler from discarding
** the overwrite before those allocations are released.  This file does not
** claim to erase allocator metadata or copies retained by dependencies.
*/

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

#include "secret.h"
#include "util.h"

/* Clear length bytes when a caller knows the allocation's exact extent. */
void
secret_clear(void *value, size_t length)
{
	if (value != NULL && length > 0)
		OPENSSL_cleanse(value, length);
}

/* Clear an owned C string, including its terminator, before releasing it. */
void
secret_free(char *value)
{
	if (value != NULL) {
		secret_clear(value, strlen(value) + 1);
		free(value);
	}
}

/* Clear every allocated buffer byte before preserving the usual free API. */
void
secret_buffer_free(struct buffer *buffer)
{
	if (buffer->data != NULL)
		secret_clear(buffer->data, buffer->cap);
	buffer_free(buffer);
}

/* Compare equal-length secret strings without an early data-byte exit. */
int
secret_equal(const char *left, const char *right)
{
	size_t left_length;
	size_t right_length;

	if (left == NULL || right == NULL)
		return 0;
	left_length = strlen(left);
	right_length = strlen(right);
	if (left_length != right_length)
		return 0;
	return CRYPTO_memcmp(left, right, left_length) == 0;
}
