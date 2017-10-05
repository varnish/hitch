#!/bin/sh

. hitch_test.sh

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

start_hitch --config=hitch.cfg

curl_hitch

NEW_PORT=$(expr $LISTENPORT + 1100)

# make a faulty config (see test19...sh)
cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$NEW_PORT"
backend = "[hitch-tls.org]:80"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
ssl = on
EOF

kill -HUP $(hitch_pid)
sleep 0.5

# Make sure the old address is still bound
curl_hitch -- "https://$LISTENADDR:$LISTENPORT/"

# Make sure the new address is not bound
hitch_hosts |
run_cmd -s 1 grep "$LISTENADDR:$NEW_PORT"
