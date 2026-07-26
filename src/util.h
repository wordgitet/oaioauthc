#ifndef OAIOAUTHC_UTIL_H
#define OAIOAUTHC_UTIL_H

#include <stddef.h>

struct buffer {
	char	*data;
	size_t	len;
	size_t	cap;
};

void	buffer_init(struct buffer *);
void	buffer_free(struct buffer *);
int	buffer_append(struct buffer *, const void *, size_t);
int	buffer_append_string(struct buffer *, const char *);
char	*buffer_steal(struct buffer *);
char	*oaio_strdup(const char *);
char	*oaio_join_path(const char *, const char *);
int	write_all(int, const void *, size_t);
int	read_file(const char *, struct buffer *);
int	write_private_file(const char *, const char *);
int	make_parent_directories(const char *);
const char	*oaio_home_dir(void);

#endif
