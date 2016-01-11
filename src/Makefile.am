
sbin_PROGRAMS = hitch

EXTRA_DIST = tests

AM_CPPFLAGS = -I/usr/include/libev/
AM_CFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE

nobase_noinst_HEADERS = ringbuffer.h configuration.h shctx.h miniobj.h vqueue.h vpf.h flopen.h uthash.h sysl_tbl.h vas.h
hitch_SOURCES = configuration.c ringbuffer.c hitch.c vpf.c flopen.c vas.c
hitch_LDADD = $(AM_LDFLAGS) -lcrypto

if USE_SHCTX
hitch_SOURCES += shctx.c
hitch_LDADD += ebtree/libebtree.a
AM_CFLAGS += -Iebtree
endif
