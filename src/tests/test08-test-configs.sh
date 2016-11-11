#!/bin/sh
# Test configuration parser.
. ${TESTDIR}/common.sh
set +o errexit

# This is a somewhat half-assed attempt at getting a usable group since the
# redhats and debians can't seem to agree on which group user "nobody"
# should be in.
GRP=`id -Gn nobody | cut -d' ' -f1`
test "$GRP" != "" || die "No usable group found for user nobody."

hitch --test --config=${CONFDIR}/default.cfg ${CERTSDIR}/default.example.com
test "$?" = "0" || die "default.cfg is not testable."

mk_cfg <<EOF
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
hitch --test --config=$CONFFILE ${CERTSDIR}/default.example.com
test "$?" = "1" || die "Invalid config test08a parsed correctly."

mk_cfg <<EOF
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
hitch --test --config=$CONFFILE ${CERTSDIR}/default.example.com
test "$?" = "1" || die "Invalid config test08b parsed correctly."

mk_cfg <<EOF
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

hitch --test --config=$CONFFILE ${CERTSDIR}/default.example.com
test "$?" = "0" || die "Valid config test08c unparseable?"

mk_cfg <<EOF
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
hitch --test --config=$CONFFILE ${CERTSDIR}/default.example.com
test "$?" = "0" || die "Valid config test08d unparseable?"

# Issue #52.
hitch --config=${CONFDIR}/default.cfg --help
test "$?" = "0" || die "--help after --config does not work as expected."

# Works as expected.
hitch --test --config=${CONFDIR}/default.cfg
test "$?" = "1" || die "--help with --config does not work as expected."

# Test that our example configuration is in fact usable.
TMPFILE=$(mktemp -u)
sed -e "s|nogroup|$GRP|" ${TESTDIR}/../../hitch.conf.example > $TMPFILE
hitch --test --config=$TMPFILE ${CERTSDIR}/default.example.com
RCODE=$?
rm $TMPFILE
if [ "$RCODE" != "0" ]; then
	die "hitch.conf.example is not valid"
fi
