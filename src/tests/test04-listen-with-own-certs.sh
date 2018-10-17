#!/bin/sh
#
# Test multiple listening sockets, each with their own certificate.
#
. hitch_test.sh

PORT2=$(expr $$ % 60000 + 4000)

start_hitch \
	--backend='[hitch-tls.org]:80' \
	--frontend="[localhost]:$LISTENPORT+${CERTSDIR}/site1.example.com" \
	--frontend="[localhost]:$PORT2+${CERTSDIR}/site2.example.com" \
	"${CERTSDIR}/default.example.com"

s_client -connect localhost:$LISTENPORT >s_client1.dump
s_client_parse s_client1.dump
run_cmd test "$SUBJECT_NAME" = "site1.example.com"

# Second listen port.
s_client -connect localhost:$PORT2 >s_client2.dump
s_client_parse s_client2.dump
run_cmd test "$SUBJECT_NAME" = "site2.example.com"

for host in $(hitch_hosts)
do
	curl_hitch -- "https://$host/"
done
