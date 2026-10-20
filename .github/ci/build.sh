#!/bin/sh
# Build hitch and run the test suite. Extra configure arguments can be
# passed through CONFIGURE_ARGS.

set -eux

JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)

# shellcheck disable=SC2086
./bootstrap ${CONFIGURE_ARGS:-}
make -j"$JOBS"
make -j"$JOBS" check VERBOSE=1
