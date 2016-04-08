#/bin/sh
#
# Test --sni-nomatch-abort
#
. ${TESTDIR}common.sh
set +o errexit

#PORT2=$(($RANDOM + 1024))

mk_cfg <<EOF
sni-nomatch-abort = on

pem-file = "${CERTSDIR}/site1.example.com"
pem-file = "${CERTSDIR}/site2.example.com"
pem-file = "${CERTSDIR}/default.example.com"

backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
}

frontend = {
	host = "$LISTENADDR"
	port = "$((LISTENPORT+1))"
	pem-file = "${CERTSDIR}/site3.example.com"
	sni-nomatch-abort = off
}

EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

# No SNI - should not be affected.
echo -e "\n" | openssl s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=default.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate on listen port #1"

# SNI request w/ valid servername
echo -e "\n" | openssl s_client -servername site1.example.com -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2"

# SNI w/ unknown servername
echo | openssl s_client -servername invalid.example.com -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
test "$?" != "0" || die "s_client did NOT fail when it should have. "
grep -q -c "unrecognized name" $DUMPFILE
test "$?" = "0" || die "Expected 'unrecognized name' error."

CURL_EXTRA="--resolve site1.example.com:$LISTENPORT:127.0.0.1"
runcurl site1.example.com $LISTENPORT

# SNI request w/ valid servername
echo -e "\n" | openssl s_client -servername site1.example.com -prexit -connect $LISTENADDR:$((LISTENPORT+1)) >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site3.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2"

# SNI w/ unknown servername
echo | openssl s_client -servername invalid.example.com -prexit -connect $LISTENADDR:$((LISTENPORT+1)) >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site3.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2"
