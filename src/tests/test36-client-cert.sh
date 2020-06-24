#!/bin/sh
# Test client-verify = required

. hitch_test.sh

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
client-verify = required
client-verify-ca = "${CERTSDIR}/client-ca.pem"
EOF

start_hitch --config=hitch.cfg

s_client -delay=1 -cert "${CERTSDIR}/client-cert01.pem"

# no client cert provided: fail
! s_client -delay=1

# cert not signed by the configured ca: failed verification
! s_client -delay=1 -cert "${CERTSDIR}/site1.example.com"
