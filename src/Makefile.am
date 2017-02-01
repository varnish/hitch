
sbin_PROGRAMS = hitch
noinst_LIBRARIES = cfg.a foreign.a

EXTRA_DIST = tests

AM_CPPFLAGS = $(EV_CFLAGS)
AM_CFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W
AM_YFLAGS = -d -t

TESTS_ENVIRONMENT = \
	TESTDIR=$(abs_top_srcdir)/src/tests/; export TESTDIR; \
	PATH=$(abs_top_builddir)/src:$(abs_top_builddir)/src/util:$$PATH; export PATH;
TESTS = @SH_TESTS@
TEST_EXTENSIONS = .sh

nobase_noinst_HEADERS = \
	asn_gentm.h \
	configuration.h \
	hitch.h \
	hssl_locks.h \
	logging.h \
	ocsp.h \
	ringbuffer.h \
	shctx.h \
	ssl_err.h \
	sysl_tbl.h \
	foreign/flopen.h \
	foreign/miniobj.h \
	foreign/uthash.h \
	foreign/vas.h \
	foreign/vpf.h \
	foreign/vqueue.h \
	foreign/vsb.h

BUILT_SOURCES = \
	cfg_lex.c \
	cfg_parser.c \
	cfg_parser.h

cfg_a_SOURCES = \
	cfg_lex.l \
	cfg_parser.y

hitch_CFLAGS = $(AM_CFLAGS) -Werror
foreign_a_SOURCES = \
	foreign/flopen.c \
	foreign/vas.c \
	foreign/vpf.c \
	foreign/vsb.c

hitch_CFLAGS = $(AM_CFLAGS) -Werror
hitch_SOURCES = \
	asn_gentm.c \
	configuration.c \
	hitch.c \
	hssl_locks.c \
	logging.c \
	ocsp.c \
	ringbuffer.c

hitch_LDADD = \
	$(SSL_LIBS) \
	$(CRYPTO_LIBS) \
	$(SOCKET_LIBS) \
	$(NSL_LIBS) \
	$(EV_LIBS) \
	$(RT_LIBS) \
	cfg.a \
	foreign.a

if USE_SHCTX
AM_CFLAGS += -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX
hitch_SOURCES += shctx.c
hitch_LDADD += ebtree/libebtree.a
AM_CFLAGS += -Iebtree
endif
