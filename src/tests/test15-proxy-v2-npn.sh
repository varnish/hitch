#!/bin/sh

. hitch_test.sh
set +o errexit

openssl s_client -help 2>&1 |
grep -q nextprotoneg ||
skip "OpenSSL does not support NPN"

BACKENDPORT=`expr $LISTENPORT + 1500`

echo Listen port is $LISTENPORT

hitch $HITCH_ARGS --backend=[127.0.0.1]:$BACKENDPORT "--frontend=[${LISTENADDR}]:$LISTENPORT" \
	--write-proxy-v2 --alpn-protos="h2,h2-14,http/1.1" \
	${CERTSDIR}/site1.example.com
test $? -eq 0 || die "Hitch did not start."

type parse_proxy_v2 || die "Can't find parse_proxy_v2"
parse_proxy_v2 $BACKENDPORT > $DUMPFILE &

sleep 0.1

# If you have nghttp installed, you can try it instead of openssl s_client:
# nghttp -v "https://localhost:$LISTENPORT"

echo -e "\n" | openssl s_client -nextprotoneg 'h2-14' -prexit -connect $LISTENADDR:$LISTENPORT > /dev/null
test $? -eq 0 || die "s_client failed"

grep -q -c "ERROR" $DUMPFILE
test $? -ne 0 || die "The utility parse_proxy_v2 gave an ERROR"

grep -q -c "h2-14" $DUMPFILE
test $? -eq 0 || die "No ALPN extension reported"

grep -q -c "ALPN extension" $DUMPFILE
test $? -eq 0 || die "No ALPN extension reported"
