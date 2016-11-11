#!/bin/sh

. ${TESTDIR}/common.sh
set +o errexit

# stud config
mk_cfg <<EOF
#
# stud(8), The Scalable TLS Unwrapping Daemon's configuration
#

# NOTE: all config file parameters can be overriden
#       from command line!

# Listening address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT
frontend = "[*]:$LISTENPORT"

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:80"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# type: string
pem-file = "${CERTSDIR}/default.example.com"

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
# type: string
ciphers = ""

# Enforce server cipher list order
#
# type: boolean
prefer-server-ciphers = off

# Use specified SSL engine
#
# type: string
ssl-engine = ""

# Number of worker processes
#
# type: integer
workers = 1

# Listen backlog size
#
# type: integer
backlog = 100

# TCP socket keepalive interval in seconds
#
# type: integer
keepalive = 3600

# Chroot directory
#
# type: string
chroot = ""

# Set uid after binding a socket
#
# type: string
user = ""

# Set gid after binding a socket
#
# type: string
group = ""

# Quiet execution, report only error messages
#
# type: boolean
quiet = off

# Use syslog for logging
#
# type: boolean
syslog = off

# Syslog facility to use
#
# type: string
syslog-facility = "daemon"

# Run as daemon
#
# type: boolean
daemon = off

# Report client address by writing IP before sending data
#
# NOTE: This option is mutually exclusive with option write-proxy and proxy-proxy.
#
# type: boolean
write-ip = off

# Report client address using SENDPROXY protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-ip and proxy-proxy.
#
# type: boolean
write-proxy = off

# Proxy an existing SENDPROXY protocol header through this request.
#
# NOTE: This option is mutually exclusive with option write-ip and write-proxy.
#
# type: boolean
proxy-proxy = off

EOF

hitch --test --config=$CONFFILE > $DUMPFILE
test "$?" = "0" || die "Hitch did not start. (config #1)"

# hitch 1.0.0
mk_cfg <<EOF
#
# Example configuration file for hitch(8).
#
# NOTE: all config file parameters can be overriden
#       from command line!

# Listening address. REQUIRED.
# Can be specified multiple times for multiple listen endpoints.
# type: string
# syntax: [HOST]:PORT[+CERT]
frontend = "[*]:$LISTENPORT"

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:80"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# type: string
pem-file = "${CERTSDIR}/default.example.com"

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
# type: string
ciphers = ""

# Enforce server cipher list order
#
# type: boolean
prefer-server-ciphers = off

# Use specified SSL engine
#
# type: string
ssl-engine = ""

# Number of worker processes
#
# type: integer
workers = 1

# Listen backlog size
#
# type: integer
backlog = 100

# TCP socket keepalive interval in seconds
#
# type: integer
keepalive = 3600

# Chroot directory
#
# type: string
chroot = ""

# Set uid after binding a socket
#
# type: string
user = ""

# Set gid after binding a socket
#
# type: string
group = ""

# Quiet execution, report only error messages
#
# type: boolean
quiet = off

# Use syslog for logging
#
# type: boolean
syslog = off

# Syslog facility to use
#
# type: string
syslog-facility = "daemon"

# Run as daemon
#
# type: boolean
daemon = off

# Report client address by writing IP before sending data
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-proxy and proxy-proxy.
#
# type: boolean
write-ip = off

# Report client address using SENDPROXY protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and proxy-proxy.
#
# type: boolean
write-proxy-v1 = off

# Report client address using SENDPROXY v2 binary protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-ip, write-proxy-v1 and proxy-proxy.
#
# type: boolean
write-proxy-v2 = off

# Proxy an existing SENDPROXY protocol header through this request.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and write-proxy-v1.
#
# type: boolean
proxy-proxy = off

# Abort handshake when the client submits an unrecognized SNI server name.
#
# type: boolean
sni-nomatch-abort = off

EOF

hitch --test --config=$CONFFILE > $DUMPFILE
test "$?" = "0" || die "Hitch did not start. (config #2)"

# 1.1.0 didn't see any config file changes
# hitch 1.2.0
mk_cfg <<EOF
#
# Example configuration file for hitch(8).
#

# Listening address. REQUIRED.
# Can be specified multiple times for multiple listen endpoints.
# type: string
# syntax: [HOST]:PORT[+CERT]
# frontend = "[*]:8443"


# Listening address. Alternative syntax
#
frontend = {
    host = "*"
    port = "$LISTENPORT"
}

# The following options can also be set in a frontend block, which
# will configure the option for this specific frontend only:
#
#    pem-file = ""
#    tls = on
#    ssl = off
#    ciphers = ""
#    prefer-server-ciphers = off
#    sni-nomatch-abort = off
#    match-global-certs = off
#
# See further explanation below for each specifc option.

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:80"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# Also available in a frontend declaration, to make a certificate
# only available for a specific listen endpoint.
#
# type: string
pem-file = "${CERTSDIR}/default.example.com"

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
#
# Option is also available in a frontend declaration.
#
# type: string
ciphers = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"

# Enforce server cipher list order
#
# Option is also available in a frontend declaration.
#
# type: boolean
prefer-server-ciphers = off

# Use specified SSL engine
#
# type: string
ssl-engine = ""

# Number of worker processes
#
# type: integer
workers = 1

# Listen backlog size
#
# type: integer
backlog = 100

# TCP socket keepalive interval in seconds
#
# type: integer
keepalive = 3600

# Chroot directory
#
# type: string
chroot = ""

# Set uid after binding a socket
#
# type: string
user = ""

# Set gid after binding a socket
#
# type: string
group = ""

# Quiet execution, report only error messages
#
# type: boolean
quiet = off

# Use syslog for logging
#
# type: boolean
syslog = off

# Syslog facility to use
#
# type: string
syslog-facility = "daemon"

# Run as daemon
#
# type: boolean
daemon = off

# Report client address by writing IP before sending data
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-proxy and proxy-proxy.
#
# type: boolean
write-ip = off

# Report client address using SENDPROXY protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and proxy-proxy.
#
# type: boolean
write-proxy-v1 = off

# Report client address using SENDPROXY v2 binary protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-ip, write-proxy-v1 and proxy-proxy.
#
# type: boolean
write-proxy-v2 = off

# Proxy an existing SENDPROXY protocol header through this request.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and write-proxy-v1.
#
# type: boolean
proxy-proxy = off

# Abort handshake when the client submits an unrecognized SNI server name.
#
# Option is also available in a frontend declaration.
#
# type: boolean
sni-nomatch-abort = off

# frontend = {
#
# # match-global-certs: Also search globally defined PEM files for SNI
# # certficiate lookups.
# # Only available in a frontend declaration.
#
#     match-global-certs = off
#
#     host = "localhost"
#     port = "443"
#     pem-file = "/etc/hitch/certs/mycert.pem"
#
# }
EOF

hitch --test --config=$CONFFILE > $DUMPFILE
test "$?" = "0" || die "Hitch did not start. (config #3)"

# hitch 1.3.0
mk_cfg <<EOF
#
# Example configuration file for hitch(8).
#

# Listening address. REQUIRED.
# Can be specified multiple times for multiple listen endpoints.
# type: string
# syntax: [HOST]:PORT[+CERT]
#frontend = "[*]:8443"


# Listening address. Alternative syntax
#
frontend = {
    host = "*"
    port = "$LISTENPORT"
}

# The following options can also be set in a frontend block, which
# will configure the option for this specific frontend only:
#
#    pem-file = ""
#    tls = on
#    ssl = off
#    ciphers = ""
#    prefer-server-ciphers = off
#    sni-nomatch-abort = off
#    match-global-certs = off
#
# See further explanation below for each specifc option.

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:80"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# Also available in a frontend declaration, to make a certificate
# only available for a specific listen endpoint.
#
# type: string
pem-file = "${CERTSDIR}/default.example.com"

# OCSP settings
#
# Directory where Hitch will store and read OCSP responses for
# stapling. Directory must be readable and writable for the configured
# hitch user. Setting this option enables automatic retrieval and
# updating of OCSP responses.
#
# ocsp-dir = "/var/lib/hitch-ocsp"

# Timeout for fetching an OCSP response from a responder (in seconds)
# ocsp-resp-tmo = 10;

# Timeout for connecting to an OCSP responder (in seconds)
# ocsp-connect-tmo = 4;

# Verification of OCSP responses
# ocsp-verify-staple = off

# If you have a manually pre-loaded OCSP staple, and alternative
# pem-file syntax can be used for stapling:
#
# pem-file = {
# 	cert = "mycert.pem"
#	ocsp-resp-file = "ocsp-resp.der"
# }

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
#
# Option is also available in a frontend declaration.
#
# type: string
ciphers = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"

# Enforce server cipher list order
#
# Option is also available in a frontend declaration.
#
# type: boolean
prefer-server-ciphers = off

# Use specified SSL engine
#
# type: string
ssl-engine = ""

# Number of worker processes
#
# type: integer
workers = 1

# Listen backlog size
#
# type: integer
backlog = 100

# TCP socket keepalive interval in seconds
#
# type: integer
keepalive = 3600

# Chroot directory
#
# type: string
chroot = ""

# Set uid after binding a socket
#
# type: string
user = ""

# Set gid after binding a socket
#
# type: string
group = ""

# Quiet execution, report only error messages
#
# type: boolean
quiet = off

# Use syslog for logging
#
# type: boolean
syslog = off

# Syslog facility to use
#
# type: string
syslog-facility = "daemon"

# Run as daemon
#
# type: boolean
daemon = off

# Report client address by writing IP before sending data
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-proxy and proxy-proxy.
#
# type: boolean
write-ip = off

# Report client address using SENDPROXY protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and proxy-proxy.
#
# type: boolean
write-proxy-v1 = off

# Report client address using SENDPROXY v2 binary protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-ip, write-proxy-v1 and proxy-proxy.
#
# type: boolean
write-proxy-v2 = off

# Proxy an existing SENDPROXY protocol header through this request.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and write-proxy-v1.
#
# type: boolean
proxy-proxy = off

# Abort handshake when the client submits an unrecognized SNI server name.
#
# Option is also available in a frontend declaration.
#
# type: boolean
sni-nomatch-abort = off

# frontend = {
#
# # match-global-certs: Also search globally defined PEM files for SNI
# # certficiate lookups.
# # Only available in a frontend declaration.
#
#     match-global-certs = off
#
#     host = "localhost"
#     port = "443"
#     pem-file = "/etc/hitch/certs/mycert.pem"
#
# }
EOF

hitch --test --config=$CONFFILE > $DUMPFILE
test "$?" = "0" || die "Hitch did not start. (config #4)"


# hitch 1.4.0
mk_cfg <<EOF
#
# Example configuration file for hitch(8).
#

# Listening address. REQUIRED.
# Can be specified multiple times for multiple listen endpoints.
# type: string
# syntax: [HOST]:PORT[+CERT]
#frontend = "[*]:8443"


# Listening address. Alternative syntax
#
frontend = {
    host = "*"
    port = "$LISTENPORT"
}

# The following options can also be set in a frontend block, which
# will configure the option for this specific frontend only:
#
#    pem-file = ""
#    tls = on
#    ssl = off
#    ciphers = ""
#    prefer-server-ciphers = off
#    sni-nomatch-abort = off
#    match-global-certs = off
#
# See further explanation below for each specifc option.

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:80"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# Also available in a frontend declaration, to make a certificate
# only available for a specific listen endpoint.
#
# type: string
pem-file = "${CERTSDIR}/default.example.com"

# OCSP settings
#
# Directory where Hitch will store and read OCSP responses for
# stapling. Directory must be readable and writable for the configured
# hitch user. Setting this option enables automatic retrieval and
# updating of OCSP responses.
#
# ocsp-dir = "/var/lib/hitch-ocsp"

# Timeout for fetching an OCSP response from a responder (in seconds)
# ocsp-resp-tmo = 10;

# Timeout for connecting to an OCSP responder (in seconds)
# ocsp-connect-tmo = 4;

# Verification of OCSP responses
# ocsp-verify-staple = off

# If you have a manually pre-loaded OCSP staple, and alternative
# pem-file syntax can be used for stapling:
#
# pem-file = {
# 	cert = "mycert.pem"
#	ocsp-resp-file = "ocsp-resp.der"
# }

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
#
# Option is also available in a frontend declaration.
#
# type: string
ciphers = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"

# Enforce server cipher list order
#
# Option is also available in a frontend declaration.
#
# type: boolean
prefer-server-ciphers = off

# Use specified SSL engine
#
# type: string
ssl-engine = ""

# Number of worker processes
#
# type: integer
workers = 1

# Listen backlog size
#
# type: integer
backlog = 100

# TCP socket keepalive interval in seconds
#
# type: integer
keepalive = 3600

# Chroot directory
#
# type: string
chroot = ""

# Set uid after binding a socket
#
# type: string
user = ""

# Set gid after binding a socket
#
# type: string
group = ""

# Quiet execution, report only error messages
#
# type: boolean
quiet = off

# Use syslog for logging
#
# type: boolean
syslog = off

# Syslog facility to use
#
# type: string
syslog-facility = "daemon"

# Run as daemon
#
# type: boolean
daemon = off

# Report client address by writing IP before sending data
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-proxy and proxy-proxy.
#
# type: boolean
write-ip = off

# Report client address using SENDPROXY protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and proxy-proxy.
#
# type: boolean
write-proxy-v1 = off

# Report client address using SENDPROXY v2 binary protocol, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details.
#
# NOTE: This option is mutually exclusive with option write-ip, write-proxy-v1 and proxy-proxy.
#
# type: boolean
write-proxy-v2 = off

# Proxy an existing SENDPROXY protocol header through this request.
#
# NOTE: This option is mutually exclusive with option write-proxy-v2, write-ip and write-proxy-v1.
#
# type: boolean
proxy-proxy = off

# Abort handshake when the client submits an unrecognized SNI server name.
#
# Option is also available in a frontend declaration.
#
# type: boolean
sni-nomatch-abort = off

# frontend = {
#
# # match-global-certs: Also search globally defined PEM files for SNI
# # certficiate lookups.
# # Only available in a frontend declaration.
#
#     match-global-certs = off
#
#     host = "localhost"
#     port = "443"
#     pem-file = "/etc/hitch/certs/mycert.pem"
#
# }

EOF

hitch --test --config=$CONFFILE > $DUMPFILE
test "$?" = "0" || die "Hitch did not start (config #5 return code: $?)"
