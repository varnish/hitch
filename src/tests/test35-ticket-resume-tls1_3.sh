#!/bin/sh
#
# Test resuming a session via a session ticket

. hitch_test.sh

if ! openssl s_client -help 2>&1 | grep -q -e "-tls1_3"
then
	skip "Missing TLSv1.3 support"
fi

start_hitch \
	--backend="[hitch-tls.org]:80" \
	--frontend="[localhost]:$LISTENPORT" \
	"${CERTSDIR}/site1.example.com"

s_client -delay=1 -tls1_3 -sess_out sess_ticket.txt >out.dump
s_client -tls1_3 -sess_in  sess_ticket.txt >in.dump

run_cmd grep Reused, in.dump
