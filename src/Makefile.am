
sbin_PROGRAMS = hitch-openssl

AM_CPPFLAGS = -I/usr/include/libev/ 
AM_CFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE

nobase_noinst_HEADERS = ringbuffer.h configuration.h .h shctx.h miniobj.h vqueue.h vpf.h flopen.h uthash.h
hitch_openssl_SOURCES = configuration.c ringbuffer.c hitch.c vpf.c flopen.c
hitch_openssl_LDADD = $(AM_LDFLAGS) -lcrypto

#if WANT_SHCTX
#hitch_SOURCES += shctx.c
#hitch_LDADD += ebtree/libebtree.a
#endif
