#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void
buffer_init(struct buffer *buffer)
{
	buffer->data = NULL;
	buffer->len = 0;
	buffer->cap = 0;
}

void
buffer_free(struct buffer *buffer)
{
	free(buffer->data);
	buffer_init(buffer);
}

int
buffer_append(struct buffer *buffer, const void *data, size_t length)
{
	size_t	needed;
	size_t	cap;
	char	*next;

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

int
buffer_append_string(struct buffer *buffer, const char *string)
{
	return buffer_append(buffer, string, strlen(string));
}

char
*buffer_steal(struct buffer *buffer)
{
	char	*data;

	if (buffer->data == NULL) {
		data = oaio_strdup("");
	} else {
		data = buffer->data;
	}
	buffer_init(buffer);
	return data;
}

char
*oaio_strdup(const char *string)
{
	size_t	length;
	char	*copy;

	length = strlen(string) + 1;
	copy = malloc(length);
	if (copy != NULL)
		memcpy(copy, string, length);
	return copy;
}

char
*oaio_join_path(const char *left, const char *right)
{
	struct buffer	buffer;

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

int
write_all(int fd, const void *data, size_t length)
{
	const char	*cursor;
	ssize_t	written;

	cursor = data;
	while (length > 0) {
		written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		cursor += written;
		length -= (size_t)written;
	}
	return 0;
}

int
read_file(const char *path, struct buffer *buffer)
{
	char	chunk[4096];
	ssize_t	count;
	int	fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;
	while ((count = read(fd, chunk, sizeof(chunk))) != 0) {
		if (count < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (buffer_append(buffer, chunk, (size_t)count) == -1) {
			close(fd);
			return -1;
		}
	}
	return close(fd);
}

int
write_private_file(const char *path, const char *data)
{
	struct buffer	temporary;
	int		fd;
	int		result;

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
	if (result == 0)
		result = rename(temporary.data, path);
	if (result == -1) {
		(void)unlink(temporary.data);
		buffer_free(&temporary);
		return -1;
	}
	buffer_free(&temporary);
	return 0;

fail:
	buffer_free(&temporary);
	return -1;
}

int
make_parent_directories(const char *path)
{
	char	*copy;
	char	*cursor;
	int	result;

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

const char
*oaio_home_dir(void)
{
	const char	*home;

	home = getenv("HOME");
	return home != NULL && home[0] != '\0' ? home : ".";
}
