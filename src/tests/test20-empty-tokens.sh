#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = ""
	pem-file = "${CERTSDIR}/default.example.com"
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "invalid config parsed correctly?"
