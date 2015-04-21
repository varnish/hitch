#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])
AC_INIT([stud], [0.1], [support@varnish-software.com])
AC_CONFIG_SRCDIR([src/configuration.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([crypto], [SSL_library_init])
AC_CHECK_LIB([ev], [ev_default_loop])
AC_CHECK_LIB([ssl], [SSL_CTX_free])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h])

AC_ARG_ENABLE([shctx],
[  --enable-shctx Enable session key exchange. Requires ebtree.],
[case "${enableval}" in
  yes) shctx=true ;;
  no)  shctx=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-shctx]) ;;
esac],[shctx=false])

AM_CONDITIONAL([WANT_SHCTX], [test x$shctx = xtrue])
AM_COND_IF([WANT_SHCTX],
           [
AC_CHECK_LIB([ebtree], [SSL_CTX_free])
AC_CONFIG_FILES([wrapper:wrapper.in])
])


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

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

AC_OUTPUT