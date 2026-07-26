/*
** Stateless OpenAI/Codex JSON conversion interface.
**
** Mutable request functions rewrite their borrowed JSON object in place.
** Functions returning json_t transfer one new Jansson reference.  Error
** buffers explain validation/conversion failures without taking ownership of
** any caller value.
*/

#ifndef OAIOAUTHC_JSON_H
#define OAIOAUTHC_JSON_H

#include <jansson.h>

/* Return an owned compact serialization. */
char	*json_dump_compact(json_t *);
/* Parse an owned-reference JSON value or provide a readable parse error. */
json_t	*json_load_string_checked(const char *, char *, size_t);
/* Construct the local error envelope used for proxy-generated failures. */
json_t	*json_error_object(const char *, const char *, int);
/* Normalize a mutable Responses request for stateless Codex operation. */
int	json_normalize_response_request(json_t *, int, char *, size_t);
/* Merge selected model metadata without replacing explicit client options. */
int	json_apply_model_defaults(json_t *, json_t *, int *, char *, size_t);
/* Detect references which require the proxy to retain prior response state. */
int	json_has_replay_state(json_t *);
/* Return a new Responses request converted from Chat Completions input. */
json_t	*json_chat_to_responses(json_t *, char *, size_t);
/* Return a new Chat Completions response converted from completed Responses. */
json_t	*json_response_to_chat(json_t *, json_t *, char *, size_t);

#endif
