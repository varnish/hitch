#!/bin/sh
# Test basic argument handling.
. ${TESTDIR}/common.sh
set +o errexit

hitch --help
test $? -eq 0 || die "--help does not work."

hitch --OBVIOUSLY_BROKEN_ARG
test $? -eq 1 || die "Wrong exit code."

hitch --version
test $? -eq 0 || die "--version does not work"
