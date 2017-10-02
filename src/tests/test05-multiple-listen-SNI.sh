#!/bin/sh
#
# Test multiple certificates (SNI) on a listening socket.
#
. hitch_test.sh
set +o errexit

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 "--frontend=[${LISTENADDR}]:$LISTENPORT" \
	${CERTSDIR}/site1.example.com ${CERTSDIR}/site2.example.com ${CERTSDIR}/default.example.com
test $? -eq 0 || die "Hitch did not start."

echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test $? -eq 0 || die "s_client failed"
grep -q -c "subject=/CN=default.example.com" $DUMPFILE
test $? -eq 0 || die "s_client got wrong certificate on listen port #1"

# send a SNI request
echo -e "\n" | openssl s_client -servername site1.example.com -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test $? -eq 0 || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test $? -eq 0 || die "s_client got wrong certificate in listen port #2"

runcurl $LISTENADDR $LISTENPORT
