#
export LC_ALL=C
set -o errexit

LISTENADDR="localhost"
LISTENPORT=$(($RANDOM + 1024))
PIDFILE="$(mktemp -u)"
CONFFILE="$(mktemp -u)"
DUMPFILE="$(mktemp -u)"
CERTSDIR="${TESTDIR}/certs"
CONFDIR="${TESTDIR}/configs"

HITCH_ARGS="--pidfile=$PIDFILE --daemon --quiet"

if [ "$USER" == "root" ]; then
	HITCH_ARGS="$HITCH_ARGS --user=nobody"
fi

cleanup() {
        test -s $PIDFILE && kill `cat "$PIDFILE"`
        rm -f "$PIDFILE" "$CONFFILE" "$DUMPFILE"
}
trap cleanup EXIT

die() {
	echo "FAILED: $*"
	if [ -r "$DUMPFILE" ]; then
		cat $DUMPFILE;
	fi
	exit 255
}

skip() {
	echo "SKIPPED: $*"
	if [ -r "$DUMPFILE" ]; then
		cat $DUMPFILE;
	fi
	exit 77
}

mk_cfg() {
	cat > "$CONFFILE"
}

runcurl() {
	# Verify that we got a HTTP reply.
	curl $CURL_EXTRA -I -X GET --max-time 5 --silent --insecure https://$1:$2/
	test "$?" = "0" || die "Incorrect HTTP response code."
}
