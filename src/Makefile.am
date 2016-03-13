
sbin_PROGRAMS = hitch

AM_CPPFLAGS = -I/usr/include/libev/
AM_CFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE
AM_YFLAGS = -d

nobase_noinst_HEADERS = ringbuffer.h configuration.h shctx.h miniobj.h \
	vqueue.h vpf.h flopen.h uthash.h sysl_tbl.h vas.h vsb.h
BUILT_SOURCES = cfg_parser.h
hitch_SOURCES = configuration.c ringbuffer.c hitch.c vpf.c flopen.c vas.c \
	cfg_parser.y cfg_lex.l vsb.c
hitch_LDADD = $(AM_LDFLAGS) -lcrypto -lfl
if USE_SHCTX
hitch_SOURCES += shctx.c
hitch_LDADD += ebtree/libebtree.a
AM_CFLAGS += -Iebtree
endif

EXTRA_DIST = tests

AM_TESTS_ENVIRONMENT = \
	TESTDIR=$(abs_top_builddir)/src/tests; export TESTDIR; \
	PATH=$(abs_top_builddir)/src:$$PATH; export PATH;

TESTS = tests/test01-start-and-stop \
	tests/test02-simple-request \
	tests/test03-multiple-listen \
	tests/test04-listen-with-own-certs \
	tests/test05-multiple-listen-SNI \
	tests/test06-ticket-resume \
	tests/test07-nomatch-abort \
	tests/test08-test-configs \
	tests/test09-wildcard-cert \
	tests/test10-dflt-certs \
	tests/test11-cfg \
	tests/test12-cfg
