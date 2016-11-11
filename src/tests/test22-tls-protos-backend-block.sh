#!/bin/sh
# Test tls-protos inside a frontend block
. ${TESTDIR}/common.sh
set +o errexit

mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.2
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

runcurl $LISTENADDR $LISTENPORT
