#!/bin/sh
# Test tls-protos in global scope
. ${TESTDIR}/common.sh
set +o errexit

# only TLSv1.2
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = TLSv1.2
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

# this will fail on platforms that have OpenSSL compiled without SSLv3
openssl s_client -connect $LISTENADDR:$LISTENPORT -tls1_2
test "$?" = "0" || die "Connecting using TLS 1.2 failed."

# this will fail on platforms that have OpenSSL compiled without SSLv3
openssl s_client -connect $LISTENADDR:$LISTENPORT -tls1_1
test "$?" != "0" || die "Connecting using TLS 1.1 succeeded when it should have failed."
