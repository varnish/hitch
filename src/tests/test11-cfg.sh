#!/bin/sh

. hitch_test.sh

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

start_hitch --config="$PWD/hitch.cfg"

curl_hitch

NEW_PORT=$(expr $LISTENPORT + 1100)

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$NEW_PORT"
backend = "[hitch-tls.org]:80"
EOF

kill -HUP "$(hitch_pid)"

sleep 1
curl_hitch -- "https://$LISTENADDR:$NEW_PORT/"

# XXX: running in a subshell to not err the test
! (curl_hitch -- "https://$LISTENADDR:$LISTENPORT/")
