
.. _hitch(8):

=====
Hitch
=====

--------------------------
high performance TLS proxy
--------------------------

:Manual section: 8

Synopsis
========

hitch [OPTIONS] [PEM]


Description
===========

Hitch is a network proxy that terminates TLS/SSL connections and forwards the
unencrypted traffic to some backend. It's designed to handle 10s of thousands of
connections efficiently on multicore machines.

Hitch has very few features -- it's designed to be paired with an intelligent
backend like Varnish Cache. It maintains a strict 1:1 connection pattern
with this backend handler so that the backend can dictate throttling behavior,
maximum connection behavior, availability of service, etc.

The only required argument is a path to a PEM file that contains the certificate
(or a chain of certificates) and private key. It should also contain
DH parameter if you wish to use Diffie-Hellman cipher suites.


Command line arguments
======================

  --config=FILE                 Load configuration from specified file. See `hitch.conf(5)` for details.
  --tls                         All TLS versions, no SSLv3 (deprecated). See config file setting ``tls-protos``.
  --ssl                         enable SSLv3 (deprecated). See config file setting ``tls-protos``.
  -c  --ciphers=SUITE           Sets allowed ciphers (Default: "")
  -e  --ssl-engine=NAME         Sets OpenSSL engine (Default: "")
  -O  --prefer-server-ciphers   Prefer server list order
  --client                      Enable client proxy mode
  -b  --backend=[HOST]:PORT     Backend [connect] (default is "[127.0.0.1]:8000")
  -f  --frontend=[HOST]:PORT[+CERT]     Frontend [bind] (default is "[*]:8443")
                                        (Note: brackets are mandatory in endpoint specifiers.)
  -n  --workers=NUM          Number of worker processes (Default: 1)
  -B  --backlog=NUM          Set listen backlog size (Default: 100)
  -k  --keepalive=SECS       TCP keepalive on client socket (Default: 3600)
  -r  --chroot=DIR           Sets chroot directory (Default: "")
  -u  --user=USER            Set uid/gid after binding the socket (Default: "")
  -g  --group=GROUP          Set gid after binding the socket (Default: "")
  -q  --quiet                Be quiet; emit only error messages
  -s  --syslog               Send log message to syslog in addition to stderr/stdout
  --syslog-facility=FACILITY    Syslog facility to use (Default: "daemon")
  --daemon               Fork into background and become a daemon;
                         this also sets the --quiet option (Default: off)
  --write-ip             Write 1 octet with the IP family followed by the IP
                         address in 4 (IPv4) or 16 (IPv6) octets little-endian
                         to backend before the actual data
                         (Default: off)
  --write-proxy-v1       Write HaProxy's PROXY v1 (IPv4 or IPv6) protocol line
                         before actual data
                         (Default: off)
  --write-proxy-v2       Write HaProxy's PROXY v2 binary (IPv4 or IPv6)  protocol line
                         before actual data
                         (Default: off)
  --write-proxy          Equivalent to --write-proxy-v2. For PROXY version 1 use
                          --write-proxy-v1 explicitly
  --proxy-proxy          Proxy HaProxy's PROXY (IPv4 or IPv6) protocol line
                         before actual data (PROXY v1 only)
                         (Default: off)
  --alpn-protos=LIST     Sets the protocols for ALPN/NPN negotiation, given by a comma
                         separated list. If this is not set explicitly, ALPN/NPN will
                         not be used. Requires OpenSSL 1.0.1 for NPN and OpenSSL 1.0.2
                         for ALPN.
  --sni-nomatch-abort    Abort handshake when client submits an unrecognized SNI server name
                         (Default: off)
  --ocsp-dir=DIR         Set OCSP staple cache directory
                         This enables automated retrieval and stapling of OCSP responses
                         (Default: "")
  -t  --test                 Test configuration and exit
  -p  --pidfile=FILE         PID file
  -V  --version              Print program version and exit
  -h  --help                 This help message


History
=======

Hitch was originally called stud and was written by Jamie Turner at Bump.com.
