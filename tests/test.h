#ifndef OAIOAUTHC_TEST_H
#define OAIOAUTHC_TEST_H

#include <stdio.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		(void)fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, \
		    __LINE__, #condition); \
		return 1; \
	} \
} while (0)

#endif
