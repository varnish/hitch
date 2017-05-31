
sbin_PROGRAMS = hitch
noinst_LIBRARIES = libcfg.a libforeign.a

EXTRA_DIST = \
	$(top_srcdir)/src/tests/common.sh \
	$(top_srcdir)/src/tests/test*.sh \
	$(top_srcdir)/src/tests/certs/* \
	$(top_srcdir)/src/tests/configs/default.cfg

AM_CFLAGS = $(HITCH_CFLAGS)
AM_YFLAGS = -d -t

TESTS_ENVIRONMENT = \
	TESTDIR=$(abs_top_srcdir)/src/tests/; export TESTDIR; \
	PATH=$(abs_top_builddir)/src:$(abs_top_builddir)/src/util:$$PATH; export PATH;
TESTS = @SH_TESTS@
TEST_EXTENSIONS = .sh
$(top_srcdir)/src/tests/test15-proxy-v2-npn.sh: $(top_builddir)/src/util/parse_proxy_v2
$(top_srcdir)/src/tests/test16-proxy-v2-alpn.sh:  $(top_builddir)/src/util/parse_proxy_v2

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

DISTCLEANFILES = cfg_parser.h cfg_parser.c

libcfg_a_SOURCES = \
	cfg_lex.l \
	cfg_parser.y

libcfg_a_CFLAGS = \
	$(AM_CFLAGS) \
	$(SSL_CFLAGS)

libforeign_a_SOURCES = \
	foreign/flopen.c \
	foreign/vas.c \
	foreign/vpf.c \
	foreign/vsb.c

hitch_SOURCES = \
	asn_gentm.c \
	configuration.c \
	hitch.c \
	hssl_locks.c \
	logging.c \
	ocsp.c \
	ringbuffer.c

hitch_CFLAGS = \
	$(AM_CFLAGS) \
	$(SSL_CFLAGS) \
	$(CRYPTO_CFLAGS) \
	$(EV_CFLAGS) \
	-Werror

hitch_LDADD = \
	$(SSL_LIBS) \
	$(CRYPTO_LIBS) \
	$(SOCKET_LIBS) \
	$(NSL_LIBS) \
	$(EV_LIBS) \
	$(RT_LIBS) \
	libcfg.a \
	libforeign.a

if USE_SHCTX
hitch_CFLAGS += -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX -Iebtree
hitch_SOURCES += shctx.c
hitch_LDADD += ebtree/libebtree.a
endif
