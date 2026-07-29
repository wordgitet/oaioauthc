/*
** Small helpers for project-owned secret allocations.
**
** These functions clear memory before releasing it, reducing the lifetime of
** OAuth credentials and local API keys in allocations owned by oaioauthc.
** They cannot clear copies held by allocators or external libraries.  String
** arguments are ordinary owned, NUL-terminated C strings unless documented
** otherwise.
*/

#ifndef OAIOAUTHC_SECRET_H
#define OAIOAUTHC_SECRET_H

#include <stddef.h>

struct buffer;

/* Overwrite one caller-owned byte range in a way the compiler cannot remove. */
void
secret_clear(void *, size_t);
/* Clear and release one owned C string; NULL is accepted. */
void
secret_free(char *);
/* Clear a buffer's complete allocation, release it, and reinitialize it. */
void
secret_buffer_free(struct buffer *);
/* Return non-zero only when two non-NULL secret strings are exactly equal. */
int
secret_equal(const char *, const char *);

#endif
