#/bin/sh
# Test configuration parser.
. ${TESTDIR}common.sh
set +o errexit

hitch --test --config=${CONFDIR}/default.cfg ${CERTSDIR}/default.example.com
test "$?" = "0" || die "default.cfg is not testable."

hitch --test --config=${CONFDIR}/test08a.cfg ${CERTSDIR}/default.example.com
test "$?" = "1" || die "Invalid config test08a.cfg parsed correctly."

hitch --test --config=${CONFDIR}/test08b.cfg ${CERTSDIR}/default.example.com
test "$?" = "1" || die "Invalid config test08b.cfg parsed correctly."

hitch --test --config=${CONFDIR}/test08c.cfg ${CERTSDIR}/default.example.com
test "$?" = "0" || die "Valid config test08c.cfg unparseable?"

hitch --test --config=${CONFDIR}/test08d.cfg ${CERTSDIR}/default.example.com
test "$?" = "0" || die "Valid config test08d.cfg unparseable?"

# Issue #52.
hitch --config=${CONFDIR}/default.cfg --help
test "$?" = "0" || die "--help after --config does not work as expected."

# Works as expected.
hitch --test --config=${CONFDIR}/default.cfg
test "$?" = "1" || die "--help with --config does not work as expected."
