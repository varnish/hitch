#!/bin/sh
#
# Test --sni-nomatch-abort
#
. hitch_test.sh

PORT2=$(expr $LISTENPORT + 701)

cat >hitch.cfg <<EOF
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
	port = "$PORT2"
	pem-file = "${CERTSDIR}/site3.example.com"
	sni-nomatch-abort = off
}
EOF

start_hitch --config="$PWD/hitch.cfg"

# No SNI - should not be affected.
s_client -connect $LISTENADDR:$LISTENPORT >no-sni.dump
run_cmd grep -q 'subject=/CN=default.example.com' no-sni.dump

# SNI request w/ valid servername
s_client -servername site1.example.com \
	-connect $LISTENADDR:$LISTENPORT >valid-sni.dump
run_cmd grep -c 'subject=/CN=site1.example.com' valid-sni.dump

# SNI w/ unknown servername
! s_client -servername invalid.example.com \
	-connect $LISTENADDR:$LISTENPORT >unknown-sni.dump
run_cmd grep 'unrecognized name' unknown-sni.dump

#HAVE_CURL_RESOLVE=`curl --help | grep -c -- '--resolve'`
#
## Disable this part of the test case if the curl version is ancient
#if [ $HAVE_CURL_RESOLVE -ne 0 ]; then
#    CURL_EXTRA="--resolve site1.example.com:$LISTENPORT:127.0.0.1"
#    runcurl site1.example.com $LISTENPORT
#fi

# SNI request w/ valid servername
s_client -servername site1.example.com -prexit \
	-connect $LISTENADDR:$PORT2 >valid-sni-2.dump
run_cmd grep -q 'subject=/CN=site3.example.com' valid-sni-2.dump

# SNI w/ unknown servername
# XXX: why don't we expect 'unrecognized name' again?
s_client -servername invalid.example.com \
	-connect $LISTENADDR:$PORT2 >unknown-sni-2.dump
run_cmd grep 'subject=/CN=site3.example.com' unknown-sni-2.dump
