
sbin_PROGRAMS = hitch

EXTRA_DIST = tests

AM_CPPFLAGS = $(EV_CFLAGS)
AM_CFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE
AM_YFLAGS = -d -t

TESTS_ENVIRONMENT = \
	TESTDIR=$(abs_top_builddir)/src/tests/; export TESTDIR; \
	PATH=$(abs_top_builddir)/src:$$PATH; export PATH;
TESTS = @SH_TESTS@
TEST_EXTENSIONS = .sh

nobase_noinst_HEADERS = ringbuffer.h configuration.h shctx.h miniobj.h \
	vqueue.h vpf.h flopen.h uthash.h sysl_tbl.h vas.h vsb.h
BUILT_SOURCES = cfg_parser.h
hitch_SOURCES = configuration.c ringbuffer.c hitch.c vpf.c flopen.c vas.c \
	cfg_parser.y cfg_lex.l vsb.c
hitch_LDADD = $(SSL_LIBS) $(CRYPTO_LIBS) $(EV_LIBS)
if USE_SHCTX
AM_CFLAGS += -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX
hitch_SOURCES += shctx.c
hitch_LDADD += ebtree/libebtree.a
AM_CFLAGS += -Iebtree
endif
