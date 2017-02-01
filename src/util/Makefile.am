
AM_CFLAGS = $(HITCH_CFLAGS)

noinst_PROGRAMS = parse_proxy_v2

parse_proxy_v2_CFLAGS = \
	$(AM_CFLAGS) \
	$(SSL_CFLAGS)

parse_proxy_v2_LDADD = \
	$(NSL_LIBS) \
	$(SOCKET_LIBS)
