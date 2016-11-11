#!/bin/sh
#
#
. ${TESTDIR}/common.sh
set +o errexit

PORT1=`expr $$ % 60000 + 1024`
PORT2=`expr $$ % 60000 + 2048`
PORT3=`expr $$ % 60000 + 3072`
PORT4=`expr $$ % 60000 + 4096`

mk_cfg <<EOF
pem-file = "${CERTSDIR}/site1.example.com"
pem-file = "${CERTSDIR}/site3.example.com"
pem-file = "${CERTSDIR}/default.example.com"
backend = "[hitch-tls.org]:80"

frontend = {
	 host = "$LISTENADDR"
	 port = "$PORT1"
	 pem-file = "${CERTSDIR}/site1.example.com"
}

frontend = {
	 host = "$LISTENADDR"
	 port = "$PORT2"
	 pem-file = "${CERTSDIR}/site2.example.com"
	 match-global-certs = on
}

frontend = {
	 host = "$LISTENADDR"
	 port = "$PORT3"
	 pem-file = "${CERTSDIR}/site3.example.com"
}

frontend = {
	 host = "$LISTENADDR"
	 port = "$PORT4"
}

EOF

hitch $HITCH_ARGS --config=$CONFFILE

test "$?" = "0" || die "Hitch did not start."

# :PORT1 without SNI
echo | openssl s_client -prexit -connect $LISTENADDR:$PORT1 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate on listen port #1"

# :PORT1 w/ SNI
echo | openssl s_client -servername site1.example.com -prexit -connect $LISTENADDR:$PORT1 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site1.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2  (expected site1.example.com)"

# :PORT1 w/ different matching SNI name
echo | openssl s_client -servername site3.example.com -prexit -connect $LISTENADDR:$PORT2 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site3.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2 (expected site3.example.com)"

# :PORT2 no SNI
echo | openssl s_client -prexit -connect $LISTENADDR:$PORT2 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=site2.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2 (expected site2.example.com)"

# :PORT4 SNI w/ unknown servername
echo | openssl s_client -servername invalid.example.com -prexit -connect $LISTENADDR:$PORT4 >$DUMPFILE 2>&1
test "$?" = "0" || die "s_client failed"
grep -q -c "subject=/CN=default.example.com" $DUMPFILE
test "$?" = "0" || die "s_client got wrong certificate in listen port #2 (expected default.example.com)"

