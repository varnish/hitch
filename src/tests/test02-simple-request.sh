#!/bin/sh
#
# Test basic argument handling.
#
. hitch_test.sh
set +o errexit

start_hitch \
	--backend=[hitch-tls.org]:80 \
	--frontend="[${LISTENADDR}]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test $? -eq 0 || die "s_client failed"

grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test $? -eq 0 || die "Got wrong certificate."

runcurl $LISTENADDR $LISTENPORT
