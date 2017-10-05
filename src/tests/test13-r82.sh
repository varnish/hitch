#!/bin/sh
#
# gh issue #82, per-frontend wildcard certificates

. hitch_test.sh

PORT1=$(expr $LISTENPORT + 1301)
PORT2=$(expr $LISTENPORT + 1302)
PORT3=$(expr $LISTENPORT + 1303)

cat >hitch.cfg <<EOF
backend = "[hitch-tls.org]:80"

tls = on
ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:CAMELLIA128-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:!LOW:!MEDIUM"
prefer-server-ciphers = on
ssl-engine = ""
sni-nomatch-abort = on

workers = 2
backlog = 100
keepalive = 3600
#chroot = "/etc/hitch"
#user = "hitch"
#group = "hitch"
quiet = off
syslog = on
syslog-facility = "daemon"
daemon = on

write-ip = off
write-proxy-v1 = off
# write-proxy-v2 = on
proxy-proxy = off

frontend = {
  host = "localhost"
  port = "$PORT1"
  pem-file = "$CERTSDIR/wildcard.example.com"
  sni-nomatch-abort = off
}

frontend = {
  host = "localhost"
  port = "$PORT2"
  pem-file = "$CERTSDIR/wildcard.example.com"
  pem-file = "$CERTSDIR/site1.example.com"
}

frontend = {
  host = "localhost"
  port = "$PORT3"
  pem-file = "$CERTSDIR/site2.example.com"
}
EOF

start_hitch --config=hitch.cfg

# Wildcard cert on frontend #1
s_client -servername foo.example.com \
	-connect localhost:$PORT1 \
	>wildcard1.dump
run_cmd grep -q '/CN=\*.example.com' wildcard1.dump

# Wildcard cert on frontend #2
s_client -servername bar.example.com \
	-connect localhost:$PORT2 \
	>wildcard2.dump
run_cmd grep -q '/CN=\*.example.com' wildcard2.dump

# Exact match on frontend #2
s_client -servername site1.example.com \
	-connect localhost:$PORT2 \
	>exact2.dump
run_cmd grep -q '/CN=site1.example.com' exact2.dump

# Verify that sni-nomatch-abort = off is respected for frontend #1
s_client -servername "asdf" \
	-connect localhost:$PORT1 \
	>abort1.dump
run_cmd grep -q '/CN=\*.example.com' abort1.dump

# And also verify that global setting sni-nomatch-abort = on is respected
# for other frontend
! s_client -servername "asdf" \
	-connect localhost:$PORT3 \
	>abort3.dump
run_cmd grep -q 'unrecognize' abort3.dump
