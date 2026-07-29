AC_PREREQ([2.69])
AC_INIT([oaioauthc], [0.2])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall])
AC_CONFIG_SRCDIR([src/app.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#ifndef __APPLE__
#error "not macOS"
#endif
]])], [AC_DEFINE([HAVE_MACOS_OPEN], [1],
    [Define to 1 when the macOS open utility is available.])])
AC_ARG_ENABLE([sanitizers],
    [AS_HELP_STRING([--enable-sanitizers],
        [build with AddressSanitizer and UndefinedBehaviorSanitizer])],
    [], [enable_sanitizers=no])
AS_IF([test "x$enable_sanitizers" = xyes], [
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"
    LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
    AC_MSG_CHECKING([whether the compiler supports requested sanitizers])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
        [AC_MSG_RESULT([yes])],
        [AC_MSG_FAILURE([AddressSanitizer and UndefinedBehaviorSanitizer are required by --enable-sanitizers])])
])
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.14])
AC_CHECK_HEADERS([sys/socket.h netinet/in.h arpa/inet.h netdb.h])
AC_CHECK_FUNCS([getaddrinfo])
AC_SEARCH_LIBS([clock_gettime], [rt], [],
    [AC_MSG_ERROR([clock_gettime is required for login deadlines])])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
