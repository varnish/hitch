#!/bin/sh
# Test configuration parser.
. hitch_test.sh

# This is a somewhat half-assed attempt at getting a usable group since the
# redhats and debians can't seem to agree on which group user "nobody"
# should be in.
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

test_cfg default <"${CONFDIR}/default.cfg"

test_bad_cfg bad1  <<EOF
frontend = "[*]:8443"
backend = "[127.0.0-1]:6086"
ciphers = "chrooert.pem"
ciphers = "chrootprefe[-server-ciphers = off
ssl-engine = ""
workers = 4
backlog =a50
keepalive = 3600
chroot = ""
user = "nobody"
group = "$GRP"
quiet = on
syslog = on
quiet = on
aemon = onwrite-ip =oxy = on
syslog = on
EOF

test_bad_cfg bad2  <<EOF
frontend = "[*]:8443"
backend = "[127.0.0.1]:6086"
ciphers = "HIGH"
prefer-server-ciphers = off
ssl-engine = ""
workers = -1
backlog = 50
keepalive = 3600
chroot = ""
user = "nobody"
group = "$GRP"
quiet = on
syslog = on
syslog-facility = "info"
daemon = on
write-ip = off
write-proxy = on
EOF

test_cfg good1  <<EOF
frontend = "[*]:8443"
backend = "[127.0.0.1]:6086"
ciphers = "HIGH"
prefer-server-ciphers = off
ssl-engine = ""
workers = 4
backlog = 50
keepalive = 3600
chroot = ""
user = "nobody"
group = "$GRP"
quiet = yes
syslog = True
syslog-facility = "daemon"
daemon = on
write-ip = n
write-proxy = on
EOF

test_cfg good2  <<EOF
# Test extra whitespace.
frontend = 		"[*]:8443"
backend =        "[127.0.0.1]:6086"		
ciphers = "HIGH"
prefer-server-ciphers = off
ssl-engine = ""
workers = 4
backlog = 50
keepalive = 3600
chroot = ""
user = "nobody"
group = "$GRP"
quiet = on
syslog = on
syslog-facility = "daemon"
daemon = "on"
write-ip = off
write-proxy = on
EOF

# Issue #52.
run_cmd hitch --config=${CONFDIR}/default.cfg --help

# Issue #22.
run_cmd -s 1 hitch --test --config=${CONFDIR}/default.cfg

# Test that our example configuration is in fact usable.
sed -e "/user /s/hitch/nobody/;/group /s/hitch/$GRP/" ${TESTDIR}/../../hitch.conf.example |
test_cfg example
