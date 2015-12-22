#
# Example configuration file for hitch(8).
#
# NOTE: all config file parameters can be overriden
#       from command line!

# Listening address. REQUIRED.
# Can be specified multiple times for multiple listen endpoints.
# type: string
# syntax: [HOST]:PORT[+CERT]
frontend = "[*]:8443"

# Upstream server address. REQUIRED.
#
# type: string
# syntax: [HOST]:PORT.
backend = "[127.0.0.1]:6081"

# SSL x509 certificate file. REQUIRED.
# List multiple certs to use SNI. Certs are used in the order they
# are listed; the last cert listed will be used if none of the others match
#
# type: string
pem-file = ""

# Password for private key in PEM file OPTIONAL.
# pem-keypass = "mypassword"
pem-keypass = "example"

# SSL protocol.
#
# tls = on
# ssl = off

# List of allowed SSL ciphers.
#
# Run openssl ciphers for list of available ciphers.
# type: string
ciphers = "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"

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

# Read client address using HAProxy PROXY protocol line, see
# http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
# for details. This address will be reported to the backend
# if one of write-ip or write-proxy is specified.
#
# type: boolean
read-proxy = off

# Report client address using X-Forwarded-For header.
#
# type: boolean
write-xff = off

# EOF
