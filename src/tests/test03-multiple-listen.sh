#!/bin/sh
#
# Test multiple listening sockets.
#
. hitch_test.sh

PORT2=$(expr $$ % 60000 + 3000)

start_hitch \
	--backend=[hitch-tls.org]:80 \
	--frontend="[localhost]:$LISTENPORT" \
	--frontend="[localhost]:$PORT2" \
	"${CERTSDIR}/site1.example.com"

for host in $(hitch_hosts)
do
	s_client -connect "$host" >"$host.dump"
	subj_name_eq "site1.example.com" "$host.dump"
	curl_hitch -- "https://$host/"
done
