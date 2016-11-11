#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

PORT1=$(($RANDOM + 1024))

echo Listen port is $LISTENPORT

hitch $HITCH_ARGS --backend=[127.0.0.1]:$PORT1 "--frontend=[${LISTENADDR}]:$LISTENPORT" ${CERTSDIR}/site1.example.com --write-proxy-v2 --alpn-protos="h2,h2-14,http/1.1"
test "$?" = "0" || die "Hitch did not start."

parse_proxy_v2 $PORT1 > $DUMPFILE &

sleep 1

# If you have nghttp installed, you can try it instead of openssl s_client:
# nghttp -v "https://localhost:$LISTENPORT"

echo -e "\n" | openssl s_client -nextprotoneg 'h2-14' -prexit -connect $LISTENADDR:$LISTENPORT > /dev/null
test "$?" = "0" || die "s_client failed"

grep -q -c "too old for NPN" $DUMPFILE
if [ "$" == "0" ]; then
    echo "Skipping test: SSL too old for NPN"
else
    grep -q -c "ERROR" $DUMPFILE
    test "$?" != "0" || die "The utility parse_proxy_v2 gave an ERROR"

    grep -q -c "h2-14" $DUMPFILE
    test "$?" = "0" || die "No ALPN extension reported"

    grep -q -c "ALPN extension" $DUMPFILE
    test "$?" = "0" || die "No ALPN extension reported"
fi
