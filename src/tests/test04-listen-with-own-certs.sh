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
subject_field_eq CN site1.example.com s_client1.dump

# Second listen port.
s_client -connect localhost:$PORT2 >s_client2.dump
subject_field_eq CN site2.example.com s_client2.dump

for host in $(hitch_hosts)
do
	curl_hitch -- "https://$host/"
done
