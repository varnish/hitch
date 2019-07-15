#!/bin/sh
# Test TLS 1.3 chipers.

. hitch_test.sh

if ! openssl s_client -help 2>&1 | grep -q -e "-tls1_3";
then
    skip "Missing TLSv1.3 support"
fi

# only TLSv1.3
cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
ciphers_v3 = "TLS_CHACHA20_POLY1305_SHA256"
tls-protos = TLSv1.3
EOF

start_hitch --config=hitch.cfg

# Get the cipher from hitch conf, not the default
s_client >s_client.dump
! grep -q "Cipher is TLS_AES_256_GCM_SHA384" s_client.dump
run_cmd grep -q "Cipher is TLS_CHACHA20_POLY1305_SHA256" s_client.dump
