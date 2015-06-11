#
export LC_ALL=C
set -o errexit

LISTENADDR="localhost"
LISTENPORT=$(($RANDOM + 1024))
PIDFILE="$(mktemp -u)"
CONFFILE="$(mktemp -u)"
DUMPFILE="$(mktemp -u)"

HITCH=../src/hitch-openssl
HITCH_ARGS="--pidfile=$PIDFILE --daemon --quiet"

cleanup() {
        test -s $PIDFILE && pkill --pidfile "$PIDFILE"
        rm -f "$PIDFILE" "$CONFFILE" "$DUMPFILE" 2>/dev/null
}
trap cleanup EXIT

die() {
	echo "FAILED: $*"
	if [ -r "$DUMPFILE" ]; then
		cat $DUMPFILE;
	fi
	exit 255
}

runcurl() {
	# Verify that we got a HTTP reply.
	BUF=$(curl $CURL_EXTRA --silent --insecure https://$1:$2/ 2>&1)
	test "$?" = "0" || die "Incorrect HTTP response code."
}
