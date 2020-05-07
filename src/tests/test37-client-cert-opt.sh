#!/bin/sh
# Test client-verify = optional

. hitch_test.sh

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
client-verify = optional
client-verify-ca = "${CERTSDIR}/client-ca.pem"
EOF

start_hitch --config=hitch.cfg

HITCH_HOST=$(hitch_hosts | sed 1q)
S_CLIENT_ARGS="-connect $HITCH_HOST -prexit"

(sleep 1; printf '\n') |
    openssl s_client $S_CLIENT_ARGS -cert "${CERTSDIR}/client-cert01.pem"

# no client cert provided: OK
(sleep 1; printf '\n') |
    openssl s_client $S_CLIENT_ARGS

# cert not signed by the configured ca: failed verification
! (sleep 1; printf '\n') |
    openssl s_client $S_CLIENT_ARGS -cert "${CERTSDIR}/site1.example.com"
