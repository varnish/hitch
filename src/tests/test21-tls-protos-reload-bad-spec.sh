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

# make a faulty config (see test19...sh)
mk_cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:`expr $LISTENPORT + 1`"
backend = "[hitch-tls.org]:80"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
ssl = on
EOF

kill -HUP $(cat $PIDFILE)
sleep 0.5
curl --max-time 5 --silent --insecure https://$LISTENADDR:`expr $LISTENPORT + 1`/
test "$?" != "0" || die "New listen endpoint should not be available."

curl --max-time 5 --silent --insecure https://$LISTENADDR:$LISTENPORT/
test "$?" = "0" || die "Old listen endpoint should be available."
