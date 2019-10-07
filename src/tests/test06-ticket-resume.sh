#!/bin/sh
#
# Test resuming a session via a session ticket

. hitch_test.sh

start_hitch \
	--backend="[hitch-tls.org]:80" \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

# XXX: why does it sometimes work with TLS 1.3? see issue 292

s_client -no_tls1_3 -sess_out sess_ticket.txt >out.dump
run_cmd test -f sess_ticket.txt
s_client -no_tls1_3 -sess_in  sess_ticket.txt >in.dump

run_cmd grep Reused, in.dump

curl_hitch
