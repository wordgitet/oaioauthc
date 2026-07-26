#ifndef OAIOAUTHC_JSON_H
#define OAIOAUTHC_JSON_H

#include <jansson.h>

char	*json_dump_compact(json_t *);
json_t	*json_load_string_checked(const char *, char *, size_t);
json_t	*json_error_object(const char *, const char *, int);
int	json_normalize_response_request(json_t *, int, char *, size_t);
int	json_has_replay_state(json_t *);
json_t	*json_chat_to_responses(json_t *, char *, size_t);
json_t	*json_response_to_chat(json_t *, json_t *, char *, size_t);

#endif
