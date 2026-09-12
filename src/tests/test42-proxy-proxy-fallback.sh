#!/bin/sh
#
# proxy-proxy-fallback: direct connections (no PROXY header) should result
# in a synthesized PROXYv2 header being sent to the backend.

. hitch_test.sh

BACKENDPORT=$(expr $LISTENPORT + 1700)

parse_proxy_v2 $BACKENDPORT >proxy.dump &

cat >hitch.cfg <<EOF
backend = "[127.0.0.1]:$BACKENDPORT"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
proxy-proxy = on
proxy-proxy-fallback = on
EOF

start_hitch --config=hitch.cfg

sleep 0.1

s_client >s_client.dump

! grep ERROR proxy.dump
run_cmd grep -q "PROXY v2 detected" proxy.dump
run_cmd grep -q "Source IP:	127.0.0.1" proxy.dump
