#!/bin/sh
# Test check_frontend_uniqueness
. hitch_test.sh

GRP=$(id -gn nobody) ||
skip 'no usable group found for user nobody'

test_cfg() {
	cfg=$1.cfg
	shift
	cat >"$cfg"
	run_cmd "$@" hitch \
		--test \
		--config="$cfg" \
		"${CERTSDIR}/default.example.com"
}

test_bad_cfg() {
	test_cfg "$1" -s 1
}
test_good_cfg() {
	test_cfg "$1" -s 0
}

test_bad_cfg bad1  <<EOF
frontend = {
host = "*"
port = "443"
}

frontend = {
host = "*"
port = "443"
}
EOF

test_good_cfg good1  <<EOF
frontend = {
host = "*"
port = "443"
}

frontend = {
host = "*"
port = "444"
}
EOF

test_good_cfg good2  <<EOF
frontend = {
host = "*"
port = "443"
}

frontend = {
host = "fd22:5979:45f3:9471::1"
port = "443"
}
EOF

test_bad_cfg bad2  <<EOF
frontend = {
host = "fd22:5979:45f3:9471::1"
port = "443"
}

frontend = {
host = "fd22:5979:45f3:9471::1"
port = "443"
}
EOF

test_good_cfg good3  <<EOF
frontend = {
host = "fd22:5979:45f3:9471::1"
port = "443"
}

frontend = {
host = "fd22:5979:45f3:9471::1"
port = "444"
}
EOF

