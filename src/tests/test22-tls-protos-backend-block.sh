#!/bin/sh
# Test tls-protos inside a frontend block

. hitch_test.sh

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.2
}
EOF

start_hitch --config=hitch.cfg
curl_hitch
