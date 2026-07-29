/*
** Minimal failure-reporting helper for standalone test binaries.
**
** CHECK returns directly from the surrounding test function, so helpers that
** require cleanup use the local REQUIRE pattern in test_proxy instead.  The
** configured program path keeps process tests independent of their working
** directory, including in out-of-tree builds.
*/

#ifndef OAIOAUTHC_TEST_H
#define OAIOAUTHC_TEST_H

#include <stdio.h>

#define TEST_PROGRAM_PATH (OAIOAUTHC_TEST_PROGRAM)

#define CHECK(condition)                                                       \
	do {                                                                   \
		if (!(condition)) {                                            \
			(void)fprintf(stderr, "%s:%d: check failed: %s\n",     \
			    __FILE__, __LINE__, #condition);                   \
			return 1;                                              \
		}                                                              \
	} while (0)

#endif
