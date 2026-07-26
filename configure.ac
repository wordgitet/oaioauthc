AC_PREREQ([2.69])
AC_INIT([oaioauthc], [0.1.0], [https://github.com/example/oaioauthc])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.14])
AC_CHECK_HEADERS([sys/socket.h netinet/in.h arpa/inet.h netdb.h])
AC_CHECK_FUNCS([getaddrinfo getrandom])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
