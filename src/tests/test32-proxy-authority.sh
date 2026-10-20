#!/bin/sh

. hitch_test.sh

BACKENDPORT=$(expr $LISTENPORT + 1600)

parse_proxy_v2 $BACKENDPORT >proxy.dump &

cat >hitch.cfg <<EOF
backend = "[127.0.0.1]:$BACKENDPORT"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
write-proxy = on
EOF

start_hitch --config=hitch.cfg

sleep 0.1

s_client -servername default.example.com >s_client.dump

! grep ERROR proxy.dump
cat proxy.dump
TAB=$(printf '\t')
run_cmd grep -q "Authority extension:${TAB}default.example.com" proxy.dump
