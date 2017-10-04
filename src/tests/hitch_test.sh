#
# To run tests manually, do:
# export TESTDIR=`pwd`/; export PATH=$PATH:`pwd`/../:`pwd`/../util/
#

set -e
# TODO: set -u

export LC_ALL=C

LISTENADDR="localhost"
LISTENPORT=`expr $$ % 62000 + 1024`
PIDFILE=$(mktemp -u)
CONFFILE=$(mktemp -u)
DUMPFILE=$(mktemp -u)
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
	test $? -eq 0 || die "Incorrect HTTP response code."
}

run_cmd() (
	set -e
	set -u

	OPTIND=1
	CMD_STATUS=0

	while getopts s: OPT
	do
		case $OPT in
		s) CMD_STATUS=$OPTARG ;;
		*) return 1 ;;
		esac
	done

	shift $((OPTIND - 1))

	printf 'Running: %s\n' "$*"

	RUN_STATUS=0
	"$@" || RUN_STATUS=$?

	if [ "$RUN_STATUS" -ne "$CMD_STATUS" ]
	then
		die "expected exit status $CMD_STATUS got $RUN_STATUS"
	fi
)
