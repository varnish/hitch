#!/bin/sh

. hitch_test.sh

BACKENDPORT=$(expr $LISTENPORT + 1600)

parse_proxy_v2 $BACKENDPORT >proxy.dump &

cat >hitch.cfg <<EOF
backend = "[127.0.0.1]:$BACKENDPORT"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
client-verify = optional
client-verify-ca = "${CERTSDIR}/client-ca.pem"
write-proxy = on
EOF

start_hitch --config=hitch.cfg

s_client -delay=1 -cert "${CERTSDIR}/client-cert01.pem"

cat proxy.dump
! grep ERROR proxy.dump
run_cmd grep "PP2_TYPE_SSL client" proxy.dump | grep -q "0x7"
run_cmd grep "PP2_TYPE_SSL verify" proxy.dump | grep -q "0x0"


parse_proxy_v2 $BACKENDPORT >proxy.dump &
# no client cert provided
s_client -delay=1

! grep ERROR proxy.dump
cat proxy.dump
run_cmd grep "PP2_TYPE_SSL client" proxy.dump | grep -q "0x1"
run_cmd grep "PP2_TYPE_SSL verify" proxy.dump | grep -q "0x1"
