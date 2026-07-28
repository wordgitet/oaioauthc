/*
** Detached daemon lifecycle and local control commands.
**
** The daemon owns its private runtime directory, advisory lock, control
** socket, metadata file, and append-only log.  The public functions borrow
** command-line strings for their synchronous call and return -1 with a
** caller-visible diagnostic on failure.
*/

#ifndef OAIOAUTHC_DAEMON_H
#define OAIOAUTHC_DAEMON_H

#include <stddef.h>
#include <stdio.h>

#include "proxy.h"

/* Start one detached proxy and wait until its listener has bound. */
int
daemon_serve(const struct proxy_options *, const char *, char *, size_t);

/* Query, stop, or stream logs from the daemon named by runtime_dir. */
int
daemon_status(const char *, FILE *, char *, size_t);
int
daemon_stop(const char *, FILE *, char *, size_t);
int
daemon_logs(const char *, int, FILE *, char *, size_t);

#endif
