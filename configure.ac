#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([hitch], [1.1.1], [support@varnish-software.com])
AC_CONFIG_SRCDIR([src/configuration.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_YACC
AC_PROG_LEX

AC_ARG_WITH([rst2man],
  AS_HELP_STRING([--with-rst2man=PATH], [Location of rst2man (auto)]),
  [RST2MAN="$withval"],
  AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [no]))
if test "x$RST2MAN" = "xno"; then
  AC_MSG_ERROR(
    [rst2man is needed to build Hitch, please install python-docutils. To proceed without building man pages, specify --with-rst2man=/bin/true.])
fi

AM_MAINTAINER_MODE([disable])

# Checks for libraries.
AC_CHECK_LIB([ev], [ev_default_loop], [], AC_MSG_ERROR([Cannot find libev headers.]))
AC_CHECK_LIB([ssl], [SSL_CTX_free], [], AC_MSG_ERROR([Cannot find libssl headers.]))

AC_ARG_ENABLE(sessioncache,
    AC_HELP_STRING([--enable-sessioncache],
		   [Enable TLS session cache. (default is off)]),
    [use_shctx="$withval"],
    [use_shctx=no])

if test xno != x"$use_shctx"; then
	CFLAGS += " -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX"
fi
AM_CONDITIONAL(USE_SHCTX, test xno != x"$use_shctx")

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([accept4])

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

AC_OUTPUT
