#
# To run tests manually, do:
# export TESTDIR=`pwd`/; export PATH=$PATH:`pwd`/../:`pwd`/../util/
#

set -e
# TODO: set -u

cd "$(mktemp -d)"
readonly TEST_TMPDIR=$(pwd)

# begin old setup

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

	cd "$TEST_TMPDIR" # just in case a test wants to cd

	for PID in *.pid
	do
		test -f "$PID" &&
		kill "$(cat "$PID")"
	done

	rm -rf "$TEST_TMPDIR"
}
trap cleanup EXIT

die() {
	echo "FAILED: $*" >&2
	if [ -r "$DUMPFILE" ]; then
		cat $DUMPFILE >&2
	fi
	exit 255
}

skip() {
	echo "SKIPPED: $*" >&2
	if [ -r "$DUMPFILE" ]; then
		cat $DUMPFILE >&2
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

# end old setup

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

	printf 'Running: %s\n' "$*" >&2

	RUN_STATUS=0
	"$@" || RUN_STATUS=$?

	if [ "$RUN_STATUS" -ne "$CMD_STATUS" ]
	then
		die "expected exit status $CMD_STATUS got $RUN_STATUS"
	fi
)

start_hitch() {
	TEST_UID=$(id -u)
	HITCH_USER=
	test "$TEST_UID" -eq 0 && HITCH_USER=--user=nobody

	run_cmd hitch \
		--pidfile="$TEST_TMPDIR/hitch.pid" \
		--daemon \
		--quiet \
		$HITCH_USER \
		"$@"
}

hitch_hosts() {
	HITCH_PID="$(cat "$TEST_TMPDIR/hitch.pid")"

	lsof -F -P -n -a -p "$HITCH_PID" -i 4 -i TCP |
	awk '/^n/ { print substr($1,2) }'
}

curl_hitch() {
	HITCH_HOST=$(hitch_hosts | sed 1q)

	CURL_STATUS=${CURL_STATUS:-200}
	RESP_STATUS=$(run_cmd curl \
		"$@" \
		--head \
		--max-time 5 \
		--silent \
		--insecure \
		--output /dev/null \
		--write-out %{http_code} \
		"https://$HITCH_HOST/")

	test "$CURL_STATUS" = "$RESP_STATUS" ||
	die "expected status $CURL_STATUS got $RESP_STATUS"
}

s_client() {
	printf 'Running: s_client %s\n' "$*" >&2

	HAS_CONNECT_OPT=false

	for ARG
	do
		# ignore non-option arguments
		test "${ARG#-}" = "$ARG" && continue

		test "$ARG" = -connect && HAS_CONNECT_OPT=true

		openssl s_client -help 2>&1 |
		grep -q -e "$ARG" ||
		skip "openssl s_client: unknown option $ARG"
	done

	if ! $HAS_CONNECT_OPT
	then
		HITCH_HOST=$(hitch_hosts | sed 1q)
		s_client "$@" -connect "$HITCH_HOST"
		return $?
	fi

	printf '\n' |
	openssl s_client -prexit "$@" 2>&1
}
