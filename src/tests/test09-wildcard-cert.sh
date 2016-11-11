#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 "--frontend=[${LISTENADDR}]:$LISTENPORT" ${CERTSDIR}/wildcard.example.com ${CERTSDIR}/default.example.com
test "$?" = "0" || die "Hitch did not start."

echo | openssl s_client -servername foo.example.com -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "/CN=\*.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2"
