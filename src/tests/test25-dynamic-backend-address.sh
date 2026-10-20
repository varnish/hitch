#!/bin/sh

# NOTE: This test does not achieve as much as it was originally (see commentet out lines), as
# - curl_hitch does not allow to parse the body. As Dridi is againts it.
# - relying on the availability of hitch-tls.org and varnish-cache.org is not the best practice


. hitch_test.sh

echo "hitch_test hitch-tls.org" >hosts
export HOSTALIASES=$PWD/hosts

getent hosts hitch_test |
grep -F hitch-tls.org ||
skip "HOSTALIASES not supported"

cat >hitch.cfg <<EOF
pem-file = "${CERTSDIR}/default.example.com"
frontend = "[localhost]:$LISTENPORT"
backend = "[hitch_test]:80"
backend-refresh = 1
EOF

start_hitch --config=hitch.cfg

curl_hitch
# TODO curl_hitch - cannot grep in output
# curl --max-time 5  --insecure https://localhost:$LISTENPORT/ >backend_refresh1.dump 2>&1
# run_cmd grep -q "<title>Hitch TLS proxy" backend_refresh1.dump

echo "hitch_test varnish-cache.org" >hosts

# The refresh depends on a real DNS lookup, give it some slack instead of
# relying on a fixed delay.
HITCH_HOST=$(hitch_hosts | sed 1q)
i=0
while [ $i -lt 15 ]
do
	sleep 1
	i=$((i + 1))
	STATUS=$(curl --head --max-time 5 --silent --insecure \
	    --output /dev/null --write-out '%{http_code}' \
	    "https://$HITCH_HOST/") || continue
	test "$STATUS" = 404 && break
done

CURL_STATUS=404
curl_hitch
# TODO curl_hitch - cannot grep in output
# curl --max-time 5  --insecure https://localhost:$LISTENPORT/ >backend_refresh2.dump 2>&1
# run_cmd grep -q "We moved the Varnish Project to a new server" backend_refresh2.dump

