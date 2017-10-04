#!/bin/sh
#
# Test multiple listening sockets.
#
. hitch_test.sh

PORT2=`expr $$ % 60000 + 3000`

start_hitch \
	--backend=[hitch-tls.org]:80 \
	--frontend="[$LISTENADDR]:$LISTENPORT" \
	--frontend="[$LISTENADDR]:$PORT2" \
	"${CERTSDIR}/site1.example.com"

for host in $(hitch_hosts)
do
	s_client -connect "$host" >$DUMPFILE
	run_cmd grep -q "subject=/CN=site1.example.com" $DUMPFILE
done

# XXX: figure how to best move those inside the loop
#runcurl $LISTENADDR $LISTENPORT
#runcurl $LISTENADDR $PORT2
