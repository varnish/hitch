#!/bin/sh

. hitch_test.sh

PORT1=$(expr $$ % 60000 + 1024)
PORT2=$(expr $$ % 60000 + 2048)
PORT3=$(expr $$ % 60000 + 3072)
PORT4=$(expr $$ % 60000 + 4096)

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/site1.example.com"
pem-file = "${CERTSDIR}/site3.example.com"
pem-file = "${CERTSDIR}/default.example.com"
backend = "[hitch-tls.org]:80"

frontend = {
	 host = "localhost"
	 port = "$PORT1"
	 pem-file = "${CERTSDIR}/site1.example.com"
}

frontend = {
	 host = "localhost"
	 port = "$PORT2"
	 pem-file = "${CERTSDIR}/site2.example.com"
	 match-global-certs = on
}

frontend = {
	 host = "localhost"
	 port = "$PORT3"
	 pem-file = "${CERTSDIR}/site3.example.com"
}

frontend = {
	 host = "localhost"
	 port = "$PORT4"
}
EOF

start_hitch --config=hitch.cfg

# :PORT1 without SNI
s_client -connect localhost:$PORT1 >port1-no-sni.dump
subject_field_eq CN "site1.example.com" port1-no-sni.dump

# :PORT1 w/ SNI
s_client -servername site1.example.com \
	-connect localhost:$PORT1 \
	>port1-sni.dump
subject_field_eq CN "site1.example.com" port1-sni.dump

# :PORT1 w/ different matching SNI name
s_client -servername site3.example.com \
	-connect localhost:$PORT2 \
	>port1-sni2.dump
subject_field_eq CN "site3.example.com" port1-sni2.dump

# :PORT2 no SNI
s_client -connect localhost:$PORT2 >port2-no-sni.dump
subject_field_eq CN "site2.example.com" port2-no-sni.dump

# :PORT4 SNI w/ unknown servername
s_client -servername invalid.example.com \
	-connect localhost:$PORT4 \
	>port4.dump
subject_field_eq CN "default.example.com" port4.dump
