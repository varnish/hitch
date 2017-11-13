#!/bin/sh
#
# Fragile test, double-check the logs on failures.

. hitch_test.sh

echo "hitch_test hitch-tls.org" >hosts
export HOSTALIASES=$PWD/hosts

getent hosts hitch_test |
grep -F hitch-tls.org ||
skip "HOSTALIASES not supported"

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[localhost]:$LISTENPORT"
backend = "[hitch_test]:80"
EOF

start_hitch --config=hitch.cfg
curl_hitch

echo "hitch_test varnish-cache.org" >hosts

sleep 2
CURL_STATUS=404
curl_hitch
