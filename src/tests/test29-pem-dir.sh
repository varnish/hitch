#!/bin/sh
#
# Test pem-dir & pem-dir-glob options
#
. hitch_test.sh
cat >hitch.cfg <<EOF
frontend = {
	host = "localhost"
	port = "$LISTENPORT"
}

pem-dir = "${CERTSDIR}/pemdirtest"
sni-nomatch-abort = on
EOF

start_hitch --config=hitch.cfg


if openssl s_client -help 2>&1 | grep -q -e -noservername;
then
	NOSNI="-noservername"
else
	NOSNI=""
fi

s_client -servername site1.example.com -connect localhost:$LISTENPORT >site1.dump
subject_field_eq CN "site1.example.com" site1.dump

s_client -servername site2.example.com -connect localhost:$LISTENPORT >site2.dump
subject_field_eq CN "site2.example.com" site2.dump

s_client -servername default.example.com -connect localhost:$LISTENPORT >default.dump
subject_field_eq CN "default.example.com" default.dump

! s_client -servername invalid.example.com -connect localhost:$LISTENPORT >unknown.dump
run_cmd grep 'unrecognized name' unknown.dump


stop_hitch
cat >hitch.cfg <<EOF
frontend = {
	host = "localhost"
	port = "$LISTENPORT"
}

pem-dir = "${CERTSDIR}/pemdirtest"
pem-dir-glob = "*site*"
sni-nomatch-abort = on
EOF

start_hitch --config=hitch.cfg

s_client -servername site1.example.com -connect localhost:$LISTENPORT >site1.dump
subject_field_eq CN "site1.example.com" site1.dump

s_client -servername site2.example.com -connect localhost:$LISTENPORT >site2.dump
subject_field_eq CN "site2.example.com" site2.dump

s_client -servername site3.example.com -connect localhost:$LISTENPORT >site3.dump
subject_field_eq CN "site3.example.com" site3.dump

! s_client -servername default.example.com -connect localhost:$LISTENPORT >default.dump
run_cmd grep 'unrecognized name' unknown.dump

s_client $NOSNI >cfg-no-sni.dump
subject_field_eq CN "site1.example.com" cfg-no-sni.dump

