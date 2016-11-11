#
# To run tests manually, do:
# export TESTDIR=`pwd`/; export PATH=$PATH:`pwd`/../:`pwd`/../util/
#
export LC_ALL=C
set -o errexit

LISTENADDR="localhost"
LISTENPORT=`expr $$ % 62000 + 1024`
PIDFILE="$(mktemp -u)"
CONFFILE="$(mktemp -u)"
DUMPFILE="$(mktemp -u)"
CERTSDIR="${TESTDIR}/certs"
CONFDIR="${TESTDIR}/configs"

HITCH_ARGS="--pidfile=$PIDFILE --daemon --quiet"

if [ "$USER" = "root" ]; then
	HITCH_ARGS="$HITCH_ARGS --user=nobody"
fi

cleanup() {
        test -f "$CONFFILE" && rm -f "$CONFFILE"
        test -f "$DUMPFILE" && rm -f "$DUMPFILE"
        if [ -s $PIDFILE ]; then
		kill `cat "$PIDFILE"`
	fi
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
