#!/bin/sh
# Test basic argument handling.

. ${TESTDIR}/common.sh

run_cmd hitch --help
run_cmd hitch --version

run_cmd -s 1 hitch --OBVIOUSLY_BROKEN_ARG
