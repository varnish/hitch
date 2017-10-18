#!/bin/sh

# read private key file and cert from 2 separate files

. hitch_test.sh
set +o errexit

CERTFILE=$(mktemp -u)
PRIVKEYFILE=$(mktemp -u)
head ${CERTSDIR}/default.example.com -n 28 > $PRIVKEYFILE
tail ${CERTSDIR}/default.example.com -n 22 | head -n 17 > $CERTFILE

mk_cfg <<EOF
pem-file = {
	cert = "$CERTFILE"
	private-key = "$PRIVKEYFILE"
}
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test $? -eq 0 || die "Hitch did not start."

rm $CERTFILE
rm $PRIVKEYFILE