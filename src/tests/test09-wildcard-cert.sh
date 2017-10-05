#!/bin/sh

. hitch_test.sh

start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[${LISTENADDR}]:$LISTENPORT" \
	"${CERTSDIR}/wildcard.example.com" \
	"${CERTSDIR}/default.example.com"

s_client -servername foo.example.com >s_client.dump
run_cmd grep -q -c "/CN=\*.example.com" s_client.dump
