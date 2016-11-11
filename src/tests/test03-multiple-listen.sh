#!/bin/sh
#
# Test multiple listening sockets.
#
. ${TESTDIR}/common.sh

PORT2=`expr $$ % 60000 + 3000`

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 \
	"--frontend=[${LISTENADDR}]:$LISTENPORT" \
	"--frontend=[${LISTENADDR}]:$PORT2" \
	${CERTSDIR}/site1.example.com
test "$?" = "0" || die "Hitch did not start."

echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE

# Second listen port.
echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$PORT2 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE

runcurl $LISTENADDR $LISTENPORT
runcurl $LISTENADDR $PORT2
