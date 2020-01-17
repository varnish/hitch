#!/bin/sh
#
# Test resuming a session via a session ticket

. hitch_test.sh

start_hitch \
	--backend="[hitch-tls.org]:80" \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

s_client -tls1_2 -sess_out sess_ticket.txt >out.dump
s_client -tls1_2 -sess_in  sess_ticket.txt >in.dump

run_cmd grep Reused, in.dump
