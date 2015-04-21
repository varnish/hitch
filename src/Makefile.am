
sbin_PROGRAMS = stud

AM_CPFLAGS = -O2 -g -std=c99 -fno-strict-aliasing -Wall -W -D_GNU_SOURCE
# -I/usr/local/include
AM_LDFLAGS = -lssl -lcrypto -lev
# AM_LDADD =  -L/usr/local/lib

nobase_noinst_HEADERS = ringbuffer.h configuration.h version.h shctx.h
stud_SOURCES = configuration.c ringbuffer.c stud.c
stud_LDFLAGS = $(STUD_LIBS) $(AM_LDFLAG)
stud_LDADD = $(AM_LDFLAGS)

if WANT_SHCTX
stud_SOURCES += shctx.c
stud_LDADD += ebtree/libebtree.a
endif
