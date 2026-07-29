/*
** Deterministic coverage for explicit project-owned secret cleansing.
**
** The test verifies memory before release through secret_clear and verifies
** the public equality contract.  It intentionally never examines memory
** after free, which would be undefined behavior.
*/

#include <string.h>

#include "secret.h"
#include "test.h"
#include "util.h"

static int
test_clear(void)
{
	unsigned char value[] = { 1, 2, 3, 4, 5 };
	static const unsigned char empty[] = { 0, 0, 0, 0, 0 };

	secret_clear(value, sizeof(value));
	return memcmp(value, empty, sizeof(value)) == 0 ? 0 : -1;
}

static int
test_equal(void)
{
	if (!secret_equal("same secret", "same secret"))
		return -1;
	if (secret_equal("same secret", "other secret") ||
	    secret_equal("short", "longer") || secret_equal(NULL, "value") ||
	    secret_equal("value", NULL))
		return -1;
	return 0;
}

static int
test_buffer_free(void)
{
	struct buffer buffer;

	buffer_init(&buffer);
	if (buffer_append_string(&buffer, "credential") == -1)
		return -1;
	secret_buffer_free(&buffer);
	return buffer.data == NULL && buffer.len == 0 && buffer.cap == 0 ? 0 : -1;
}

int
main(void)
{
	CHECK(test_clear() == 0);
	CHECK(test_equal() == 0);
	CHECK(test_buffer_free() == 0);
	return 0;
}
