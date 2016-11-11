#!/bin/sh
#
# Test multiple listening sockets, each with their own certificate.
#
. ${TESTDIR}/common.sh
set +o errexit

PORT2=`expr $$ % 60000 + 4000`

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 \
	"--frontend=[${LISTENADDR}]:$LISTENPORT+${CERTSDIR}/site1.example.com" \
	"--frontend=[${LISTENADDR}]:$PORT2+${CERTSDIR}/site2.example.com" \
	${CERTSDIR}/default.example.com
test "$?" = "0" || die "Hitch did not start."

echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1 || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate on listen port #1"

# Second listen port.
echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$PORT2 >$DUMPFILE 2>&1 || die "s_client failed"
grep -q -c "subject=/CN=site2.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2"

runcurl $LISTENADDR $LISTENPORT
runcurl $LISTENADDR $PORT2
