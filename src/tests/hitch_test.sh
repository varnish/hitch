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
CERTSDIR="${TESTDIR}/certs"
CONFDIR="${TESTDIR}/configs"

# end old setup

dump() {
	for DUMP in *.dump
	do
		test -f "$DUMP" || continue

		printf '\nFound dump file %s:\n\n' "$DUMP"
		cat -v "$DUMP" | sed -e 's/^/> /'
	done >&2
}

cleanup() {
	for PID in *.pid
	do
		test -f "$PID" &&
		kill "$(cat "$PID")"
	done

	rm -rf "$TEST_TMPDIR"
}

trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	dump
	exit 255
}

skip() {
	echo "SKIP: $*" >&2
	dump
	exit 77
}

error() {
	echo "ERROR: $*" >&2
	dump
	exit 99
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

	printf 'Running: %s\n' "$*" >&2

	RUN_STATUS=0
	"$@" || RUN_STATUS=$?

	if [ "$RUN_STATUS" -ne "$CMD_STATUS" ]
	then
		fail "expected exit status $CMD_STATUS got $RUN_STATUS"
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

hitch_pid() {
	cat "$TEST_TMPDIR/hitch.pid"
}

hitch_hosts() {
	lsof -F -P -n -a -p "$(hitch_pid)" -i 4 -i TCP |
	awk '/^n/ { print substr($1,2) }'
}

curl_hitch() {
	printf 'Running: curl %s\n' "$*" >&2

	HAS_SPECIFIC_ARG=false

	for ARG
	do
		test "$ARG" = -- && HAS_SPECIFIC_ARG=true

		# ignore non-option arguments
		test "${ARG#-}" = "$ARG" && continue

		curl --help |
		grep -q -e "$ARG" ||
		skip "curl: unknown option $ARG"
	done

	if ! $HAS_SPECIFIC_ARG
	then
		HITCH_HOST=$(hitch_hosts | sed 1q)
		curl_hitch "$@" -- "https://$HITCH_HOST/"
		return $?
	fi

	CURL_STATUS=${CURL_STATUS:-200}
	EXIT_STATUS=0
	RESP_STATUS=$(curl \
		--head \
		--max-time 5 \
		--silent \
		--verbose \
		--insecure \
		--output /dev/null \
		--write-out '%{http_code}' \
		"$@") || EXIT_STATUS=$?

	# XXX: how to handle the cases where we expect an error?
	test $EXIT_STATUS -ne 0 &&
	error "curl request failed or timed out (exit status: $EXIT_STATUS)"

	test "$CURL_STATUS" = "$RESP_STATUS" ||
	fail "expected status $CURL_STATUS got $RESP_STATUS"
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
