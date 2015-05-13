
sbin_PROGRAMS = hitch

AM_CPPFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE -I/usr/include/libev
AM_LDFLAGS = -lssl -lcrypto -lev

nobase_noinst_HEADERS = ringbuffer.h configuration.h version.h shctx.h miniobj.h vqueue.h
hitch_SOURCES = configuration.c ringbuffer.c hitch.c
hitch_LDFLAGS = $(hitch_LIBS) $(AM_LDFLAG)
hitch_LDADD = $(AM_LDFLAGS)

#if WANT_SHCTX
#hitch_SOURCES += shctx.c
#hitch_LDADD += ebtree/libebtree.a
#endif
