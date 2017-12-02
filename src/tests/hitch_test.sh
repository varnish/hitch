#
# This file contains test helpers for the Hitch test suite, reusable bits of
# code shared by at least two test cases.
#
# To run tests manually, do:
# export TESTDIR=`pwd`/; export PATH=$PATH:`pwd`/../:`pwd`/../util/
#

#-
# We want the shell to catch errors for us and fail as soon as a command
# fails or an undefined variable is used (often typos for the latter).

set -e
set -u

#-
# We give each test its own directory to simplify file management, this
# directory is then removed by the exit trap below.

cd "$(mktemp -d)"
readonly TEST_TMPDIR=$(pwd)

#-
# This was part of the old setup, and should be ported to something more
# robust in the future.

export LC_ALL=C

LISTENPORT=`expr $$ % 62000 + 1024`
CERTSDIR="${TESTDIR}/certs"
CONFDIR="${TESTDIR}/configs"


#-
# When a test fails, give as much context as possible for troubleshooting. It
# looks for file in the test's directory, but not recursively. The dump is
# currently done when an explicit failure triggers, and could leave us in the
# dark if we a "naked" command fails and is caught by `set -e`. We can wrap
# any command with the `run_cmd` helper to trigger a failure.

dump() {
	for LOG in *.log
	do
		test -f "$LOG" || continue

		printf '\nFound log file %s:\n\n' "$LOG"
		cat -v "$LOG" | sed -e 's/^/> /'
	done >&2

	for DUMP in *.dump
	do
		test -f "$DUMP" || continue

		printf '\nFound dump file %s:\n\n' "$DUMP"
		cat -v "$DUMP" | sed -e 's/^/> /'
	done >&2
}

#-
# The exit trap removes the test directory before the shell exits.

cleanup() {
	for PID in *.pid
	do
		test -f "$PID" &&
		kill "$(cat "$PID")"
	done

	rm -rf "$TEST_TMPDIR"
}

trap cleanup EXIT

#-
# Explicit failures, following-ish automake conventions for exit statuses.
# Using any of these commands in a sub-shell is pointless because the
# exit status would be that of the sub-shell instead of the test itself.
#
# This however, is OK:
#
# some --command |
# something --else ||
# fail "some message"

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

#-
# Usage: run_cmd [-s status] command [args...]
#
# By default expect a zero exit status, takes care of explicitly failing if
# the exit status doesn't match expectations.
#
# Should not be used in a sub-shell.

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

#-
# Usage: start_hitch [args...]
#
# Start a hitch daemon, taking care of the common parameters, with the
# possibility to add more parameters. Only one hitch daemon can be started
# in a single test case.
#
# Should not be used in a sub-shell.

start_hitch() {
	TEST_UID=$(id -u)
	HITCH_USER=
	test "$TEST_UID" -eq 0 && HITCH_USER=--user=nobody

	run_cmd hitch \
		--pidfile="$TEST_TMPDIR/hitch.pid" \
		--log-filename=hitch.log \
		--daemon \
		$HITCH_USER \
		"$@"
}

#-
# Usage: hitch_pid
#
# Print the PID of the daemon started with `start_hitch`, usually in a
# sub-shell for a different command.
#
# Example
#
# kill -HUP $(hitch_pid)

hitch_pid() {
	cat "$TEST_TMPDIR/hitch.pid"
}

#-
# Usage: hitch_hosts
#
# Print a list of hosts for the daemon started with `start_hitch`, usually in
# a loop.

hitch_hosts() {
	if command -v lsof >/dev/null
	then
		lsof -F -P -n -a -p "$(hitch_pid)" -i 4 -i TCP |
		sed 's/*/localhost/' |
		awk '/^n/ { print substr($1,2) }'
		return
	fi

	if command -v sockstat >/dev/null
	then
		sockstat -P tcp |
		awk '$3 == '"$(hitch_pid)"' {print $6}' |
		sort |
		uniq |
		sed 's:\*:localhost:'
		return
	fi

	if command -v fstat >/dev/null
	then
		fstat -p "$(hitch_pid)" |
		awk '$7 == "tcp" { gsub("\\*", "localhost", $9); print $9 }'
		return
	fi

	fail "none of lsof, sockstat or fstat available"
}

#-
# Usage: curl_hitch [opts...] [-- arg [args...]]
#
# Send an HTTPS request to a hitch server. If an option is not supported by
# curl the test is skipped. When `--` is missing, a URL using the first
# address reported by `hitch_host` is used. It includes all the common options
# needed by test cases. The test fail if the response status is different than
# ${CURL_STATUS} (or 200 if it isn't set).
#
# Should not be used in a sub-shell.

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

#-
# Usage: [!] s_client [args...]
#
# Frontend to `openssl s_client` with the common options we usually need. It
# specifies the `-connect` option unless it was part of the arguments. A new
# line is sent via the standard input. It doesn't use `run_cmd` because some
# executions are expected to yield a non-zero exit status, in that case just
# negate the result.
#
# Expect a success:
#
# s_client [...]
#
# Expect a failure:
#
# ! s_client [...]
#
# When we expect a failure, it usually to then inspect the output, and for
# convenience the standard error is redirected to the standard output.
#
# Should not be used in a sub-shell.

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
