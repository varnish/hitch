#!/bin/sh

. hitch_test.sh

BACKENDPORT=$(expr $LISTENPORT + 1600)

parse_proxy_v2 $BACKENDPORT >proxy.dump &

cat >hitch.cfg <<EOF
backend = "[127.0.0.1]:$BACKENDPORT"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = TLSv1.2
ciphers = "ECDHE-RSA-AES256-GCM-SHA384"
write-proxy = on
EOF

start_hitch --config=hitch.cfg

sleep 0.1

s_client -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384 >s_client.dump

! grep ERROR proxy.dump
cat proxy.dump
run_cmd grep -q ECDHE-RSA-AES256-GCM-SHA384 proxy.dump
run_cmd grep -q TLSv1.2 proxy.dump
