#!/bin/sh
# Test basic argument handling.
. ${TESTDIR}/common.sh
set +o errexit

hitch --help
test "$?" = "0" || die "--help does not work."

hitch --OBVIOUSLY_BROKEN_ARG
test "$?" = "1" || die "Wrong exit code."

hitch --version
test "$?" = "0" || die "--version does not work"
