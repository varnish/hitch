#!/bin/sh
#
# Test basic argument handling.
#
. hitch_test.sh

start_hitch \
	--backend="[hitch-tls.org]:80" \
	--frontend="[${LISTENADDR}]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

s_client -prexit -connect $LISTENADDR:$LISTENPORT >$DUMPFILE
run_cmd grep -q "subject=/CN=site1.example.com" $DUMPFILE

curl_hitch
