#!/bin/sh
# Test TLS 1.3 availability.

. hitch_test.sh

# only TLSv1.3
cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
EOF

start_hitch --config=hitch.cfg

# this will fail on platforms that have OpenSSL without TLS 1.3.
s_client -tls1_3
