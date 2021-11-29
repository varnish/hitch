#!/bin/sh

# read private key file and cert from 2 separate files

. hitch_test.sh

head -n 28 ${CERTSDIR}/default.example.com > priv.key
tail -n 25 ${CERTSDIR}/default.example.com | head -n 17 >cert.crt

cat >hitch.cfg <<EOF
pem-file = {
	cert = "cert.crt"
	private-key = "priv.key"
}
frontend = "[localhost]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

start_hitch --config=hitch.cfg
