AM_CPPFLAGS = -D_POSIX_C_SOURCE=200809L -I$(top_srcdir)/src $(LIBCURL_CFLAGS) $(OPENSSL_CFLAGS) $(JANSSON_CFLAGS)
AM_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror
check_PROGRAMS = test_auth test_images test_json test_sse test_proxy test_login \
	test_local
TESTS = $(check_PROGRAMS)
noinst_HEADERS = test.h
test_auth_SOURCES = test_auth.c ../src/auth.c ../src/http.c ../src/json.c ../src/util.c
test_images_SOURCES = test_images.c ../src/images.c ../src/json.c ../src/util.c
test_json_SOURCES = test_json.c ../src/json.c ../src/util.c
test_sse_SOURCES = test_sse.c ../src/sse.c ../src/json.c ../src/util.c
test_proxy_SOURCES = test_proxy.c ../src/util.c
test_login_SOURCES = test_login.c ../src/util.c
test_local_SOURCES = test_local.c ../src/util.c
test_auth_LDADD = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS)
test_images_LDADD = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS)
test_json_LDADD = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS)
test_sse_LDADD = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS)
