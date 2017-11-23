#!/bin/sh

. hitch_test.sh

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = {
	 host = "*"
	 port = "$LISTENPORT"
	 pem-file = "${CERTSDIR}/default.example.com"
	 tls = on
	 ciphers = "HIGH"
	 prefer-server-ciphers = on
}
EOF

start_hitch --config=hitch.cfg
curl_hitch
