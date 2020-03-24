/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to 1 if you have the `accept4' function. */
#define HAVE_ACCEPT4 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <linux/futex.h> header file. */
#define HAVE_LINUX_FUTEX_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* OpenSSL has SSL_CTX_get_default_passwd_cb() */
#define HAVE_SSL_CTX_GET_DEFAULT_PASSWD_CB 1

/* OpenSSL has SSL_CTX_get_default_passwd_cb_userdata() */
#define HAVE_SSL_CTX_GET_DEFAULT_PASSWD_CB_USERDATA 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if `s3' is a member of `struct ssl_st'. */
/* #undef HAVE_STRUCT_SSL_ST_S3 */

/* Define to 1 if `st_mtim' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_MTIM 1

/* Define to 1 if `st_mtimespec' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_MTIMESPEC */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if TLSv1.3 is available */
#define HAVE_TLS_1_3 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* OpenSSL has X509_NAME_ENTRY_get_data() */
#define HAVE_X509_NAME_ENTRY_GET_DATA 1

/* OpenSSL supports ALPN */
#define OPENSSL_WITH_ALPN 1

/* OpenSSL needs explicit locking */
/* #undef OPENSSL_WITH_LOCKS */

/* OpenSSL supports NPN */
#define OPENSSL_WITH_NPN 1

/* Name of package */
#define PACKAGE "hitch"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "opensource@varnish-software.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "hitch"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "hitch 1.5.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "hitch"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.5.2"

/* Define if SO_REUSEPORT works */
#define SO_REUSEPORT_WORKS 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* TCP Fast Open is enabled */
#define TCP_FASTOPEN_WORKS 1

/* sessioncache is enabled */
/* #undef USE_SHARED_CACHE */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "1.5.2"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif
