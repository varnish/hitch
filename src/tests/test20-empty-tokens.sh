#!/bin/sh

. hitch_test.sh

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = ""
	pem-file = "${CERTSDIR}/default.example.com"
}
EOF

run_cmd -s 1 hitch --test --config=hitch.cfg
