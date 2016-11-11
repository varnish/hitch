#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

mk_cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

runcurl $LISTENADDR $LISTENPORT

mk_cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:`expr $LISTENPORT + 1100`"
backend = "[hitch-tls.org]:80"
EOF

kill -HUP $(cat $PIDFILE)
sleep 1
runcurl $LISTENADDR `expr $LISTENPORT + 1100`

curl --max-time 5 --silent --insecure https://$LISTENADDR:$LISTENPORT/
test "$?" != "0" || die "Removed listen endpoint should not be available."
