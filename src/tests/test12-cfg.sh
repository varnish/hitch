#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = {
	 host = "*"
	 port = "`expr $LISTENPORT + 1200`"
	 pem-file = "${CERTSDIR}/default.example.com"
	 tls = on
	 ciphers = "HIGH"
	 prefer-server-ciphers = on
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

runcurl $LISTENADDR `expr $LISTENPORT + 1200`
