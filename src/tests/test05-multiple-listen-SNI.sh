#!/bin/sh
#
# Test multiple certificates (SNI) on a listening socket.

. hitch_test.sh

start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com" \
	"${CERTSDIR}/site2.example.com" \
	"${CERTSDIR}/default.example.com"

s_client >no-sni.dump
subject_field_eq CN "default.example.com" no-sni.dump

# send a SNI request
s_client -servername site1.example.com >sni.dump
subject_field_eq CN "site1.example.com" sni.dump

curl_hitch

stop_hitch

cat >hitch.cfg <<EOF
frontend = {
       host = "localhost"
       port = "$LISTENPORT"

       pem-file = "${CERTSDIR}/site1.example.com"
       pem-file = "${CERTSDIR}/site2.example.com"
       pem-file = "${CERTSDIR}/default.example.com"
}

backend = "[hitch-tls.org]:80"
EOF

start_hitch --config=hitch.cfg

s_client >cfg-no-sni.dump
subject_field_eq CN "default.example.com" cfg-no-sni.dump

s_client -servername site1.example.com >cfg-sni.dump
subject_field_eq CN "site1.example.com" cfg-sni.dump

s_client -servername SITE1.EXAMPLE.COM >cfg-sni-upper.dump
subject_field_eq CN "site1.example.com" cfg-sni-upper.dump
