#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([hitch], [1.5.0], [opensource@varnish-software.com])
AC_CONFIG_SRCDIR([src/configuration.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([.])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([
	-Wall
	-Werror
	foreign
	color-tests
	parallel-tests
	subdir-objects
])
AM_PROG_AR

# Checks for programs.
AM_PROG_CC_C_O
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_ARG_WITH([lex],
	AS_HELP_STRING([--with-lex], [Build with lex]),
	[], [with_lex=no])
AC_ARG_WITH([yacc],
	AS_HELP_STRING([--with-yacc], [Build with yacc]),
	[], [with_yacc=no])
AC_ARG_ENABLE([documentation],
	AS_HELP_STRING([--enable-documentation], [Build the documentation]),
	[], [enable_documentation=no])

test "$with_lex" = yes && AC_PROG_LEX
test "$with_yacc" = yes && AC_PROG_YACC

AM_CONDITIONAL([ENABLE_DOCUMENTATION], [test "$enable_documentation" = yes])

AM_COND_IF([ENABLE_DOCUMENTATION], [
	AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [no])
	if test "$RST2MAN" = no
	then
		AC_MSG_ERROR([rst2man is needed to build the documentation])
	fi
])

AC_CHECK_PROGS(SOCKSTAT, [lsof sockstat fstat], [no])
if test "x$SOCKSTAT" = xno; then
	AC_MSG_WARN([No tool found for socket inspection, tests will fail.])
fi

AM_MAINTAINER_MODE([disable])

# Checks for libraries.
PKG_CHECK_EXISTS([libev], [
	PKG_CHECK_MODULES([EV], [libev])], [
	HITCH_SEARCH_LIBS([EV], [ev], [ev_default_loop],
		[AC_MSG_ERROR([Cannot find libev.])])
])

PKG_CHECK_MODULES([SSL], [libssl])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
HITCH_SEARCH_LIBS([SOCKET], [socket], [socket])
HITCH_SEARCH_LIBS([NSL], [nsl], [inet_ntop])
HITCH_SEARCH_LIBS([RT], [rt], [clock_gettime])

AC_CHECK_MEMBERS([struct stat.st_mtim, struct stat.st_mtimespec])

AC_ARG_ENABLE(sessioncache,
    AC_HELP_STRING([--enable-sessioncache],
		   [Enable TLS session cache. (default is off)]),
    [use_shctx="$enableval"],
    [use_shctx=no])
if test x"$use_shctx" != xno; then
  if test ! -e 'src/ebtree/ebtree.h'; then
    AC_MSG_ERROR([Must clone https://github.com/haproxy/ebtree to src/ebtree/])
  fi
  AC_DEFINE([USE_SHARED_CACHE], [1], [sessioncache is enabled])
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
AC_FUNC_MMAP
AC_CHECK_FUNCS([accept4])

AC_CACHE_CHECK([whether SO_REUSEPORT works],
  [ac_cv_so_reuseport_works],
  [AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
    ]], [[
	int s = socket(AF_INET, SOCK_STREAM, 0);
	int i = 5;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &i, sizeof i) < 0)
	  return (1);
	return (0);
]])],
  [ac_cv_so_reuseport_works=yes],
  [ac_cv_so_reuseport_works=no])
  ]
)
if test "$ac_cv_so_reuseport_works" = yes; then
  AC_DEFINE([SO_REUSEPORT_WORKS], [1], [Define if SO_REUSEPORT works])
fi

AC_ARG_ENABLE(tcp-fastopen,
	AC_HELP_STRING([--enable-tcp-fastopen],
		[Enable TCP Fast Open. (default is auto)]),
	[use_tfo="$enableval"],
	[use_tfo=auto])

if test x"$use_tfo" != xno; then
	AC_CACHE_CHECK([whether TCP_FASTOPEN works],
		[ac_cv_so_tfo],
		[AC_RUN_IFELSE(
			[AC_LANG_PROGRAM([[
				#include <sys/types.h>
				#include <sys/socket.h>
				#include <netinet/tcp.h>
			]], [[
				int s = socket(AF_INET, SOCK_STREAM, 0);
				int i = 5;
				if (setsockopt(s, SOL_TCP, TCP_FASTOPEN, &i, sizeof i) < 0)
				return (1);
				return (0);
			]])],
		[ac_cv_so_tfo=yes],
		[ac_cv_so_tfo=no])
		]
	)
	if test "$ac_cv_so_tfo" != yes && test use_tfo = yes; then
		AC_MSG_ERROR([Socket option TCP_FASTOPEN is not supported by the kernel])
	fi
	if test "$ac_cv_so_tfo" = yes; then
		AC_DEFINE([TCP_FASTOPEN_WORKS], [1], [TCP Fast Open is enabled])
	fi
fi

AC_CHECK_HEADERS([linux/futex.h])
AM_CONDITIONAL([HAVE_LINUX_FUTEX], [test $ac_cv_header_linux_futex_h = yes])

SH_TESTS="$(cd $srcdir/src && echo tests/test*.sh)"
AC_SUBST(SH_TESTS)

dnl Desired CFLAGS
HITCH_CHECK_FLAGS([HITCH_CFLAGS], [
	-O2
	-g
	-Wall
	-W
])

AC_SUBST([HITCH_CFLAGS])

dnl Help libev macros
HITCH_CHECK_FLAGS([EV_CFLAGS], [-fno-strict-aliasing])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/util/Makefile
])

AC_OUTPUT
