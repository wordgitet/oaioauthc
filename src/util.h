/*
** Shared allocation, I/O, and private-file helpers.
**
** All functions follow ordinary C ownership: returned char pointers are owned
** by the caller, while buffer functions own buffer->data until buffer_steal.
** File helpers return -1 with errno from the failed system operation.
*/

#ifndef OAIOAUTHC_UTIL_H
#define OAIOAUTHC_UTIL_H

#include <stddef.h>

/*
** Growable byte buffer.
**
** data is either NULL for an empty unallocated buffer or points to cap bytes.
** len excludes the maintained trailing NUL.  No caller may retain data across
** an append that can reallocate it.
*/
struct buffer {
	char  *data;
	size_t len;
	size_t cap;
};

/* Initialize/release a reusable growable byte buffer. */
void
buffer_init(struct buffer *);
void
buffer_free(struct buffer *);
/* Append binary or string data while maintaining a trailing NUL. */
int
buffer_append(struct buffer *, const void *, size_t);
int
buffer_append_string(struct buffer *, const char *);
/* Transfer the backing allocation and reset the source buffer. */
char *
buffer_steal(struct buffer *);
/* Return owned copies of a C string or joined path fragments. */
char *
oaio_strdup(const char *);
char *
oaio_join_path(const char *, const char *);
/* Complete an interrupted short-write loop or read an entire file. */
int
write_all(int, const void *, size_t);
int
read_file(const char *, struct buffer *);
/* Atomically write mode-0600 text and create private parent directories. */
int
write_private_file(const char *, const char *);
int
make_parent_directories(const char *);
/* Return HOME or a current-directory fallback when HOME is unavailable. */
const char *
oaio_home_dir(void);

#endif
