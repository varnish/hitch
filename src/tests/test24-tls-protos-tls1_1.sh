#!/bin/sh
# Test tls-protos in global scope

. hitch_test.sh

if ! openssl s_client -help 2>&1 | grep -q -e "-ssl3"
then
	skip "Missing SSLv3 support"
fi

# only TLSv1.1
cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = TLSv1.1
EOF

start_hitch --config=hitch.cfg

# this will fail on platforms that have OpenSSL compiled without SSLv3
! s_client -tls1_2
s_client -tls1_1
