#!/bin/sh
# Test specifying combinations of ssl, tls and tls-protos in different ways.
# All of these invocations of hitch shall fail, or something is wrong

. hitch_test.sh

test_bad_cfg() {
	run_cmd -s 1 hitch --test --config="$1"
}

test_both_cfg() {
	frontend_cfg="$1.frontend.cfg"
	global_cfg="$1.global.cfg"

	printf 'backend = "[hitch-tls.org]:80"\n\n' |
	tee "$frontend_cfg" "$global_cfg"

	printf 'frontend = {\n' >>"$frontend_cfg"

	tee -a "$frontend_cfg" "$global_cfg"

	printf '}\n' >>"$frontend_cfg"

	test_bad_cfg "$frontend_cfg"
	test_bad_cfg "$global_cfg"
}

# "tls-protos = " then "ssl = on"
test_both_cfg tls-protos-then-ssl-on <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
	ssl = on
}
EOF

# "ssl = on" then "tls-protos = "
test_both_cfg ssl-on-then-tls-protos <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	ssl = on
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
}
EOF

# "tls-protos = " then "tls = on"
test_both_cfg tls-protos-then-tls-on <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
	tls = on
}
EOF

# "tls = on" then "tls-protos = "
test_both_cfg tls-on-then-tls-protos <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls = on
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
}
EOF

# "ssl = on" then "tls = off"
test_both_cfg ssl-on-then-tls-off <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	ssl = on
	tls = off
}
EOF

# "tls = on" then "ssl = off"
test_both_cfg tls-on-then-ssl-off <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "localhost"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls = on
	ssl = off
}
EOF
