#!/bin/sh
#
# Test resuming a session via a session ticket

. ${TESTDIR}/common.sh
set +o errexit

SESSFILE=`mktemp`
rmsess() {
	rm -f $SESSFILE
	cleanup
}
trap rmsess EXIT

hitch $HITCH_ARGS --backend=[hitch-tls.org]:80 "--frontend=[${LISTENADDR}]:$LISTENPORT" \
	${CERTSDIR}/site1.example.com
test "$?" = "0" || die "Hitch did not start."

echo -e "\n" | openssl s_client -prexit -sess_out $SESSFILE -connect $LISTENADDR:$LISTENPORT
test "$?" = "0" || die "s_client failed (1)"

echo -e "\n" | openssl s_client -prexit -sess_in $SESSFILE -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed (2)"

grep -q -c "Reused, " $DUMPFILE
test "$?" = "0" || die "Unable to resume session via session ticket."

runcurl $LISTENADDR $LISTENPORT
