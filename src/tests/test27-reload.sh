#!/bin/sh

. hitch_test.sh

cp ${CERTSDIR}/default.example.com cert.pem

# XXX: reload doesn't work with a relative pem file
cat >hitch.cfg <<EOF
pem-file = "$PWD/cert.pem"
frontend = "[localhost]:$LISTENPORT"
backend = "[hitch-tls.org]:80"
EOF

# XXX: reload doesn't work with a relative config file
start_hitch --config=$PWD/hitch.cfg

s_client >s_client1.dump
subject_field_eq CN "default.example.com" s_client1.dump

# restart hitch after having a more recent cert file
cp ${CERTSDIR}/ecc.example.com.pem cert.pem
echo "kill -HUP $(hitch_pid)"
kill -HUP $(hitch_pid)
sleep 2

s_client | tee s_client2.dump
subject_field_eq CN "ecc.example.com" s_client2.dump
