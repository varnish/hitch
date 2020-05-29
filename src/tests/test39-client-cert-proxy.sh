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

HITCH_HOST=$(hitch_hosts | sed 1q)
S_CLIENT_ARGS="-connect $HITCH_HOST -prexit"

(sleep 1; printf '\n') |
    openssl s_client $S_CLIENT_ARGS -cert "${CERTSDIR}/client-cert01.pem"

cat proxy.dump
! grep ERROR proxy.dump
run_cmd grep "PP2_TYPE_SSL client" proxy.dump | grep -q "0x7"
run_cmd grep "PP2_TYPE_SSL verify" proxy.dump | grep -q "0x0"


parse_proxy_v2 $BACKENDPORT >proxy.dump &
# no client cert provided
(sleep 1; printf '\n') |
    openssl s_client $S_CLIENT_ARGS

! grep ERROR proxy.dump
cat proxy.dump
run_cmd grep "PP2_TYPE_SSL client" proxy.dump | grep -q "0x1"
! run_cmd grep "PP2_TYPE_SSL verify" proxy.dump | grep -q "0x0"
