#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit
unset SSL_CERT_DIR
unset SSL_CERT_FILE

mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "$LISTENADDR"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
	 ocsp-resp-file = "$CERTSDIR/valid.example.com.ocsp"
	 ocsp-verify-staple = on
}
EOF

hitch --test $HITCH_ARGS --config=$CONFFILE
test "$?" != "0" || die "Hitch started when it shouldn't have."

export SSL_CERT_FILE=$CERTSDIR/valid.example.com-ca-chain.pem
hitch --test $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

unset SSL_CERT_FILE

mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "$LISTENADDR"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
	 ocsp-resp-file = "$CERTSDIR/valid.example.com.ocsp"
	 ocsp-verify-staple = off
}
EOF

hitch --test $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."

# Test that timeouts are valid configuration file entries. Actually
# testing the timeouts will be complicated and is deemed unnecessary for now.
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "$LISTENADDR"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
}

ocsp-connect-tmo = 10
ocsp-resp-tmo = 10
EOF

hitch --test $HITCH_ARGS --config=$CONFFILE
test "$?" = "0" || die "Hitch did not start."
