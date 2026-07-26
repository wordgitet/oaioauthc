AM_CPPFLAGS = -D_POSIX_C_SOURCE=200809L $(LIBCURL_CFLAGS) $(OPENSSL_CFLAGS) $(JANSSON_CFLAGS)
AM_CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror
bin_PROGRAMS = oaioauthc
oaioauthc_SOURCES = \
	main.c \
	app.c app.h \
	auth.c auth.h \
	http.c http.h \
	json.c json.h \
	proxy.c proxy.h \
	sse.c sse.h \
	util.c util.h
oaioauthc_LDADD = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS)
