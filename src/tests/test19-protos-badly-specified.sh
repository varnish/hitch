#!/bin/sh
# Test specifying combinations of ssl, tls and tls-protos in different ways.
# All of these invocations of hitch shall fail, or something is wrong
. ${TESTDIR}/common.sh
set +o errexit

##########
# In frontend blocks

# "tls-protos = " then "ssl = on" in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
	ssl = on
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "ssl = on" then "tls-protos = " in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	ssl = on
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls-protos = " then "tls = on" in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
	tls = on
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls = on" then "tls-protos = " in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls = on
	tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "ssl = on" then "tls = off" in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	ssl = on
	tls = off
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls = on" then "ssl = off" in frontend block
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
	host = "$LISTENADDR"
	port = "$LISTENPORT"
	pem-file = "${CERTSDIR}/default.example.com"
	tls = on
	ssl = off
}
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

##########################
# global scope specs

# "tls-protos = " then "ssl = on" in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
ssl = on
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "ssl = on" then "tls-protos = " in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
ssl = on
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls-protos = " then "tls = on" in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
tls = on
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls = on" then "tls-protos = " in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls = on
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "ssl = on" then "tls = off" in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
ssl = on
tls = off
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."

# "tls = on" then "ssl = off" in global scope
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls = on
ssl = off
EOF

hitch $HITCH_ARGS --config=$CONFFILE
test "$?" = "1" || die "Wrong exit code."


##########################
# specifying --ssl or --tls in the command line

# both --tls and --ssl in the command line
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
EOF

hitch $HITCH_ARGS --config=$CONFFILE --ssl --tls
test "$?" = "1" || die "Wrong exit code."

# tls-protos, then --tls in the command line
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
EOF

hitch $HITCH_ARGS --config=$CONFFILE --tls
test "$?" = "1" || die "Wrong exit code."

# tls-protos, then --ssl in the command line
mk_cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"
pem-file = "${CERTSDIR}/default.example.com"
tls-protos = SSLv3 TLSv1.0 TLSv1.1 TLSv1.2
EOF

hitch $HITCH_ARGS --config=$CONFFILE --ssl
test "$?" = "1" || die "Wrong exit code."
