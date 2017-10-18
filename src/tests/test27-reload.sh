#!/bin/sh

# restart hitch after having a more recent cert file

. hitch_test.sh
set +o errexit

CERTFILE=$(mktemp -u)
cp ${CERTSDIR}/default.example.com $CERTFILE

mk_cfg <<EOF
pem-file = "$CERTFILE"
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test $? -eq 0 || die "Hitch did not start."

openssl s_client -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
grep -q -c "CN=default.example.com" $DUMPFILE
test $? -eq 0 || die "Incorrect certificate"

cp ${CERTSDIR}/ecc.example.com.pem $CERTFILE
touch $CERTFILE

kill -HUP $(cat $PIDFILE)
sleep 1

# curl --max-time 5  --insecure https://$LISTENADDR:$LISTENPORT/ >$DUMPFILE 2>&1
openssl s_client -connect $LISTENADDR:$LISTENPORT >$DUMPFILE 2>&1
grep -q -c "CN=ecc.example.com" $DUMPFILE
test $? -eq 0 || die "Incorrect certificate"


rm $CERTFILE