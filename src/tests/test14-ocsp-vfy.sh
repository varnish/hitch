#!/bin/sh

. hitch_test.sh

unset SSL_CERT_DIR
unset SSL_CERT_FILE

cat >hitch1.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "localhost"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
	 ocsp-resp-file = "$CERTSDIR/valid.example.com.ocsp"
	 ocsp-verify-staple = on
}
EOF

run_cmd -s 1 hitch --test --config=hitch1.cfg

export SSL_CERT_FILE=$CERTSDIR/valid.example.com-ca-chain.pem
run_cmd hitch --test --config=hitch1.cfg

unset SSL_CERT_FILE

cat >hitch2.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "localhost"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
	 ocsp-resp-file = "$CERTSDIR/valid.example.com.ocsp"
	 ocsp-verify-staple = off
}
EOF

run_cmd hitch --test --config=hitch2.cfg

# Test that timeouts are valid configuration file entries. Actually
# testing the timeouts will be complicated and is deemed unnecessary for now.
cat >hitch3.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
  host = "localhost"
  port = "$LISTENPORT"
}

pem-file = {
	 cert = "$CERTSDIR/valid.example.com"
}

ocsp-connect-tmo = 10
ocsp-resp-tmo = 10
EOF

run_cmd hitch --test --config=hitch3.cfg
