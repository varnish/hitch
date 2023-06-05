#!/bin/sh
# Test client-verify in pem-block = {}

. hitch_test.sh

PORT2=$(expr $LISTENPORT + 23)

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"
frontend = "[*]:$LISTENPORT"

pem-file = {
    cert = "${CERTSDIR}/site1.example.com"
    client-verify = required
    client-verify-ca = "${CERTSDIR}/client-ca.pem"
}

frontend = {
    host = "*"
    port = "$PORT2"

    pem-file = {
        cert = "${CERTSDIR}/site3.example.com"
        client-verify = required
        client-verify-ca = "${CERTSDIR}/client-ca.pem"
    }

    pem-file = "${CERTSDIR}/site2.example.com"
}

pem-file = "${CERTSDIR}/default.example.com"
EOF

start_hitch --config=hitch.cfg

HITCH_HOST1=$(hitch_hosts | sed -n 1p)
HITCH_HOST2=$(hitch_hosts | sed -n 2p)

# hit default cert: no client verification
s_client -delay=1 -connect "$HITCH_HOST1"

# hit default cert via sni: no client verification
s_client -delay=1 -servername default.example.com -connect "$HITCH_HOST1"

# fails: client certificate required
! s_client -delay=1 -servername site1.example.com -connect "$HITCH_HOST1"

# cert provided: OK
s_client -delay=1 -servername site1.example.com -cert "${CERTSDIR}/client-cert01.pem" -connect "$HITCH_HOST1"

# site2.example.com: OK. No client verification required
s_client -delay=1 -servername site2.example.com -connect "$HITCH_HOST2"

# site3: fails: cert required
! s_client -delay=1 -servername site3.example.com -connect "$HITCH_HOST2"

# site3: cert provided: OK
s_client -delay=1 -servername site2.example.com -connect "$HITCH_HOST2" -cert "${CERTSDIR}/client-cert01.pem"

stop_hitch

# Also verify that a pem-file definition overrides a frontend
# definition
cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"

frontend = {
    host = "*"
    port = "$LISTENPORT"

    pem-file = {
        cert = "${CERTSDIR}/site1.example.com"
        client-verify = required
        client-verify-ca = "${CERTSDIR}/client-ca.pem"
    }

    client-verify = none
    pem-file = "${CERTSDIR}/default.example.com"
}


EOF

start_hitch --config=hitch.cfg
HITCH_HOST=$(hitch_hosts | sed -n 1p)

# default: no client verification
s_client -delay=1

# hit default cert via sni: no client verification
s_client -delay=1 -servername default.example.com

# fails: client certificate required
! s_client -delay=1 -servername site1.example.com -connect "$HITCH_HOST1"

# cert provided: OK
s_client -delay=1 -servername site1.example.com -cert "${CERTSDIR}/client-cert01.pem" -connect "$HITCH_HOST1"
