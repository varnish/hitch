#!/bin/sh
# Test tls-protos in global scope

. hitch_test.sh

# only TLSv1.2
cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = TLSv1.2
EOF

start_hitch --config=hitch.cfg

# this will fail on platforms that have OpenSSL compiled without SSLv3
# XXX: find how to detect the lack of SSLv3
s_client -tls1_2

# this will fail on platforms that have OpenSSL compiled without SSLv3
! s_client -tls1_1
