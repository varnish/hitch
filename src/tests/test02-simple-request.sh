#!/bin/sh
#
# Test basic argument handling.
#
. ${TESTDIR}/common.sh
set +o errexit

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 "--frontend=[${LISTENADDR}]:$LISTENPORT" ${CERTSDIR}/site1.example.com
test "$?" = "0" || die "Hitch did not start."

echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"

grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test "$?" = "0" || die "Got wrong certificate."

runcurl $LISTENADDR $LISTENPORT
