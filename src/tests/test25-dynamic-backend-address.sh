#!/bin/sh

. hitch_test.sh
set +o errexit

TMP_HOSTS_FILE=`mktemp`
echo "hitch_test hitch-tls.org" > $TMP_HOSTS_FILE
export HOSTALIASES=$TMP_HOSTS_FILE

mk_cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[$LISTENADDR]:$LISTENPORT"
backend = "[hitch_test]:80"
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test $? -eq 0 || die "Hitch did not start."

runcurl $LISTENADDR $LISTENPORT
curl --max-time 5  --insecure https://$LISTENADDR:$LISTENPORT/ >$DUMPFILE 2>&1
test $? -eq 0 || die "Old backend address should be available."
grep  "<title>Hitch TLS proxy" $DUMPFILE
test $? -eq 0 || die "Old backend served unexpected site"

echo "hitch_test varnish-cache.org" > $TMP_HOSTS_FILE

sleep 2
runcurl $LISTENADDR $LISTENPORT

curl --max-time 5  --insecure https://$LISTENADDR:$LISTENPORT/ >$DUMPFILE 2>&1
test $? -eq 0 || die "New backend address should be available."
grep -q -c "We moved the Varnish Project to a new server" $DUMPFILE
test $? -eq 0 || die "New backend served unexpected site"

rm $TMP_HOSTS_FILE

