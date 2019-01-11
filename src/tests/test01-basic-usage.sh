#!/bin/sh
# Test basic argument handling.

. hitch_test.sh

run_cmd hitch --help
run_cmd hitch --version

run_cmd -s 1 hitch --OBVIOUSLY_BROKEN_ARG
