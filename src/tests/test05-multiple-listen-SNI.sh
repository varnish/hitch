#!/bin/sh
#
# Test multiple certificates (SNI) on a listening socket.

. hitch_test.sh

start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[${LISTENADDR}]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com" \
	"${CERTSDIR}/site2.example.com" \
	"${CERTSDIR}/default.example.com"

s_client >no-sni.dump
run_cmd grep -q 'subject=/CN=default.example.com' no-sni.dump

# send a SNI request
s_client -servername site1.example.com >sni.dump
run_cmd grep -q 'subject=/CN=site1.example.com' sni.dump

curl_hitch
