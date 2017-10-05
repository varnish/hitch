#!/bin/sh

. hitch_test.sh

BACKENDPORT=`expr $LISTENPORT + 1500`

parse_proxy_v2 $BACKENDPORT >proxy.dump &

start_hitch \
	--backend=[127.0.0.1]:$BACKENDPORT \
	--frontend="[localhost]:$LISTENPORT" \
	--write-proxy-v2 \
	--alpn-protos="h2,h2-14,http/1.1" \
	${CERTSDIR}/site1.example.com

sleep 0.1

# If you have nghttp installed, you can try it instead of openssl s_client:
# nghttp -v "https://localhost:$LISTENPORT"

s_client -nextprotoneg 'h2-14' >s_client.dump

! grep ERROR proxy.dump

run_cmd grep -q h2-14 proxy.dump
run_cmd grep -q "ALPN extension" proxy.dump

# XXX: why do we expect ALPN and not NPN here?
