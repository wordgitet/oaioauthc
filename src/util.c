/*
** Small ownership and filesystem primitives shared by the program.
**
** buffer is a growable byte container with two simultaneous guarantees: len
** is authoritative for binary callers, while data is always NUL-terminated
** after a successful append for parsers that need a C string.  buffer_steal
** transfers ownership of data and resets the source buffer to its initial
** state.
**
** Credential writes use a sibling temporary file, mode 0600, fsync, and
** rename.  This avoids readers seeing a partially written auth.json and keeps
** new token files private even when the process umask is permissive.  Parent
** directories are created with mode 0700 only as needed for that path.
*/

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

/* Return non-zero when authority is one literal loopback host with a port. */
static int
loopback_authority(const char *authority, size_t length)
{
	const char    *port;
	size_t	      host_length;
	unsigned long number;
	unsigned long digit;

	host_length = 0;
	if ((length == 9 || (length > 9 && authority[9] == ':')) &&
	    memcmp(authority, "localhost", 9) == 0)
		host_length = 9;
	else if ((length == 9 || (length > 9 && authority[9] == ':')) &&
	    memcmp(authority, "127.0.0.1", 9) == 0)
		host_length = 9;
	else if ((length == 5 || (length > 5 && authority[5] == ':')) &&
	    memcmp(authority, "[::1]", 5) == 0)
		host_length = 5;
	if (host_length == 0)
		return (0);
	if (length == host_length)
		return (1);
	port = authority + host_length + 1;
	if (port == authority + length)
		return (0);
	number = 0;
	while (port < authority + length) {
		if (*port < '0' || *port > '9')
			return (0);
		digit = (unsigned long)(*port - '0');
		if (number > (65535UL - digit) / 10)
			return (0);
		number = number * 10 + digit;
		port++;
	}
	return (number > 0);
}

/*
** Accept an HTTPS URL or a deliberately local HTTP endpoint.
**
** OAuth credentials may be posted to these URLs.  The parser is intentionally
** conservative: userinfo, control characters, and non-loopback HTTP hosts
** are rejected before libcurl can make a connection.
*/
int
url_is_secure_or_loopback(const char *url)
{
	const unsigned char *cursor;
	const char	    *authority;
	const char	    *authority_end;
	size_t		     authority_length;
	int		     secure;

	if (url == NULL || url[0] == '\0')
		return (0);
	for (cursor = (const unsigned char *)url; *cursor != '\0'; cursor++) {
		if (*cursor <= 0x20 || *cursor == 0x7f || *cursor == '\\')
			return (0);
	}
	if (strncmp(url, "https://", 8) == 0) {
		authority = url + 8;
		secure = 1;
	} else if (strncmp(url, "http://", 7) == 0) {
		authority = url + 7;
		secure = 0;
	} else
		return (0);
	authority_end = strpbrk(authority, "/?#");
	if (authority_end == NULL)
		authority_end = authority + strlen(authority);
	authority_length = (size_t)(authority_end - authority);
	if (authority_length == 0 ||
	    memchr(authority, '@', authority_length) != NULL)
		return (0);
	return (secure || loopback_authority(authority, authority_length));
}

/*
** Initialize buffer for first use.  No allocation occurs here, and the result
** may be passed to buffer_free or buffer_steal even if no bytes are appended.
*/
void
buffer_init(struct buffer *buffer)
{
	buffer->data = NULL;
	buffer->len = 0;
	buffer->cap = 0;
}

/* Release the owned allocation, then restore the initialization invariant. */
void
buffer_free(struct buffer *buffer)
{
	free(buffer->data);
	buffer_init(buffer);
}

/*
** Append length bytes to buffer.
**
** On success, buffer owns the combined bytes and data[len] is NUL.  On
** failure, overflow and allocation checks leave the existing buffer intact.
** The input may be binary and may alias no part of a future reallocation.
*/
int
buffer_append(struct buffer *buffer, const void *data, size_t length)
{
	size_t needed;
	size_t cap;
	char  *next;

	/* Reserve one trailing NUL while keeping len valid for binary callers. */
	if (length > (size_t)-1 - buffer->len - 1)
		return -1;
	needed = buffer->len + length + 1;
	if (needed > buffer->cap) {
		cap = buffer->cap == 0 ? 256 : buffer->cap;
		while (cap < needed) {
			if (cap > (size_t)-1 / 2)
				return -1;
			cap *= 2;
		}
		next = realloc(buffer->data, cap);
		if (next == NULL)
			return -1;
		buffer->data = next;
		buffer->cap = cap;
	}
	memcpy(buffer->data + buffer->len, data, length);
	buffer->len += length;
	buffer->data[buffer->len] = '\0';
	return 0;
}

/* Append a C string without including its terminator in buffer->len. */
int
buffer_append_string(struct buffer *buffer, const char *string)
{
	return buffer_append(buffer, string, strlen(string));
}

/*
** Transfer buffer's allocation to the caller and reset buffer.
**
** Empty buffers still return an allocated empty string.  This avoids forcing
** every caller that hands a buffer to a string API to special-case NULL.
*/
char *
buffer_steal(struct buffer *buffer)
{
	char *data;

	if (buffer->data == NULL) {
		data = oaio_strdup("");
	} else {
		data = buffer->data;
	}
	buffer_init(buffer);
	return data;
}

/* Allocate and copy one NUL-terminated string, or return NULL on allocation. */
char *
oaio_strdup(const char *string)
{
	size_t length;
	char  *copy;

	length = strlen(string) + 1;
	copy = malloc(length);
	if (copy != NULL)
		memcpy(copy, string, length);
	return copy;
}

/*
** Join two path fragments with exactly the separator needed between them.
**
** The caller owns the returned string.  This helper does not canonicalize
** paths: preserving the supplied fragments is important for user-selected
** credential locations and avoids changing symlink resolution semantics.
*/
char *
oaio_join_path(const char *left, const char *right)
{
	struct buffer buffer;

	buffer_init(&buffer);
	if (buffer_append_string(&buffer, left) == -1 ||
	    (left[0] != '\0' && left[strlen(left) - 1] != '/' &&
		buffer_append_string(&buffer, "/") == -1) ||
	    buffer_append_string(&buffer, right) == -1) {
		buffer_free(&buffer);
		return NULL;
	}
	return buffer_steal(&buffer);
}

/*
** Write the full byte range, retrying interrupted writes.
**
** A short positive write is normal and advances the cursor.  Any other I/O
** error is returned to the caller unchanged through errno.
*/
int
write_all(int fd, const void *data, size_t length)
{
	const char *cursor;
	ssize_t	    written;

	cursor = data;
	while (length > 0) {
		written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (written == 0) {
			errno = EIO;
			return -1;
		}
		cursor += written;
		length -= (size_t)written;
	}
	return 0;
}

/*
** Read an entire file into an initialized buffer.
**
** The file is read in bounded chunks and EINTR is retried.  A read or append
** failure leaves any bytes already accumulated available to the caller, which
** must still release the buffer; this mirrors ordinary realloc ownership.
*/
int
read_file(const char *path, struct buffer *buffer)
{
	char	chunk[4096];
	ssize_t count;
	int	fd;
	int	result;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;
	result = -1;
	while ((count = read(fd, chunk, sizeof(chunk))) != 0) {
		if (count < 0) {
			if (errno == EINTR)
				continue;
			goto done;
		}
		if (buffer_append(buffer, chunk, (size_t)count) == -1)
			goto done;
	}
	result = 0;

done:
	if (close(fd) == -1 && result == 0)
		return -1;
	return result;
}

/*
** Write private text through a synchronized sibling temporary file.
**
** replace selects atomic rename over an existing destination.  A new-only
** installation uses link instead, whose EEXIST result guarantees that a file
** created after the caller's initial check is never replaced.
*/
static int
write_private_file_internal(const char *path, const char *data, int replace)
{
	struct buffer temporary;
	int	      fd;
	int	      result;
	int	      saved_errno;

	/* Write and sync a 0600 temporary before exposing its complete contents. */
	if (make_parent_directories(path) == -1)
		return -1;
	buffer_init(&temporary);
	if (buffer_append_string(&temporary, path) == -1 ||
	    buffer_append_string(&temporary, ".tmp.XXXXXX") == -1) {
		buffer_free(&temporary);
		return -1;
	}
	fd = mkstemp(temporary.data);
	if (fd == -1)
		goto fail;
	result = fchmod(fd, 0600);
	if (result == 0)
		result = write_all(fd, data, strlen(data));
	if (result == 0)
		result = fsync(fd);
	if (close(fd) == -1)
		result = -1;
	if (result == 0) {
		if (replace)
			result = rename(temporary.data, path);
		else
			result = link(temporary.data, path);
	}
	if (result == -1) {
		saved_errno = errno;
		(void)unlink(temporary.data);
		buffer_free(&temporary);
		errno = saved_errno;
		return -1;
	}
	/*
	 * The destination is complete once link succeeds.  A cleanup failure may
	 * leave a private sibling, but must not report that credentials were not
	 * installed when path already names the synchronized inode.
	 */
	if (!replace)
		(void)unlink(temporary.data);
	buffer_free(&temporary);
	return 0;

fail:
	buffer_free(&temporary);
	return -1;
}

/*
** Atomically replace path with private text data.
**
** Readers see the previous complete file or the synchronized replacement.
*/
int
write_private_file(const char *path, const char *data)
{
	return write_private_file_internal(path, data, 1);
}

/*
** Atomically install path only if it remains absent.
**
** link provides the no-replace operation required to keep a credential file
** that appears during an interactive login from being overwritten silently.
*/
int
write_private_file_new(const char *path, const char *data)
{
	return write_private_file_internal(path, data, 0);
}

/*
** Create every missing directory component preceding path with mode 0700.
**
** Existing directories are accepted without inspecting their mode or owner;
** callers use this only for a user-selected credential path, where refusing
** an existing directory would be more surprising than using it.
*/
int
make_parent_directories(const char *path)
{
	char *copy;
	char *cursor;
	int   result;

	copy = oaio_strdup(path);
	if (copy == NULL)
		return -1;
	result = 0;
	for (cursor = copy + 1; *cursor != '\0'; cursor++) {
		if (*cursor != '/')
			continue;
		*cursor = '\0';
		if (mkdir(copy, 0700) == -1 && errno != EEXIST) {
			result = -1;
			break;
		}
		*cursor = '/';
	}
	free(copy);
	return result;
}

/* Return HOME when available, otherwise the relative "." fallback. */
const char *
oaio_home_dir(void)
{
	const char *home;

	home = getenv("HOME");
	return home != NULL && home[0] != '\0' ? home : ".";
}
