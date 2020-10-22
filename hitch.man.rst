.. role:: ref(emphasis)

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

``--config=FILE``
-----------------

Load configuration from specified file.  See `hitch.conf(5)` for
details.

``--tls-protos=LIST``
---------------------

Specifies which SSL/TLS protocols to use.  Available tokens are
``SSLv3``, ``TLSv1.0``, ``TLSv1.1``, ``TLSv1.2`` and
``TLSv1.3``. (Default "TLSv1.2 TLSv1.3")

``-c  --ciphers=SUITE``
-----------------------

Sets allowed ciphers (Default:
"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH")

``-e  --ssl-engine=NAME``
-------------------------

Sets OpenSSL engine (Default: "")

``-O  --prefer-server-ciphers[=on|off]``
----------------------------------------

Prefer server list order (Default: "off")

``--client``
------------

Enable client proxy mode

``-b  --backend=[HOST]:PORT``
-----------------------------

Backend endpoint (default is "[127.0.0.1]:8000") The -b argument can
also take a UNIX domain socket path E.g. --backend="/path/to/sock"

``-f  --frontend=[HOST]:PORT[+CERT]``
-------------------------------------

Frontend listen endpoint (default is "[*]:8443") (Note: brackets are
mandatory in endpoint specifiers.)

``-n  --workers=NUM``
---------------------

Number of worker processes (Default: 1)

``-B  --backlog=NUM``
---------------------

Set listen backlog size (Default: 100)

``-k  --keepalive=SECS``
------------------------

TCP keepalive on client socket (Default: 3600)

``-R  --backend-refresh=SECS``
------------------------------

Periodic backend IP lookup, 0 to disable (Default: 0)

``--enable-tcp-fastopen[=on|off]``
----------------------------------

Enable client-side TCP Fast Open. (Default: off)

``-r  --chroot=DIR``
--------------------

Sets chroot directory (Default: "")

``-u  --user=USER``
-------------------

Set uid/gid after binding the socket (Default: "")

``-g  --group=GROUP``
---------------------

Set gid after binding the socket (Default: "")

``-q  --quiet[=on|off]``
------------------------

Be quiet; emit only error messages (deprecated, use 'log-level')

``-L  --log-level=NUM``
-----------------------

Log level. 0=silence, 1=err, 2=info/debug (Default: 1)

``-l  --log-filename=FILE``
---------------------------

Send log message to a logfile instead of stderr/stdout

``-s  --syslog[=on|off]``
-------------------------

Send log message to syslog in addition to stderr/stdout

``--syslog-facility=FACILITY``
------------------------------

Syslog facility to use (Default: "daemon")

``--daemon[=on|off]``
---------------------

Fork into background and become a daemon (Default: off)

``--write-ip[=on|off]``
-----------------------

Write 1 octet with the IP family followed by the IP address in 4
(IPv4) or 16 (IPv6) octets little-endian to backend before the actual
data (Default: off)

``--write-proxy-v1[=on|off]``
-----------------------------

Write HAProxy's PROXY v1 (IPv4 or IPv6) protocol line before actual
data (Default: off)

``--write-proxy-v2[=on|off]``
-----------------------------

Write HAProxy's PROXY v2 binary (IPv4 or IPv6) protocol line before
actual data (Default: off)

``--write-proxy[=on|off]``
--------------------------

Equivalent to --write-proxy-v2. For PROXY version 1
use --write-proxy-v1 explicitly

``--proxy-proxy[=on|off]``
--------------------------

Proxy HAProxy's PROXY (IPv4 or IPv6) protocol before actual data
(PROXYv1 and PROXYv2) (Default: off)

``--sni-nomatch-abort[=on|off]``
--------------------------------

Abort handshake when client submits an unrecognized SNI server name
(Default: off)

``--alpn-protos=LIST``
----------------------

Sets the protocols for ALPN/NPN negotiation, provided as a list of
comma-separated tokens.

``--ocsp-dir=DIR``
------------------

Set OCSP staple cache directory This enables automated retrieval and
stapling of OCSP responses (Default: "/var/lib/hitch/")

``-t  --test``
--------------

Test configuration and exit

``-p  --pidfile=FILE``
----------------------

PID file

``-V  --version``
-----------------

Print program version and exit

``-h  --help``
--------------

This help message


History
=======

Hitch was originally called stud and was written by Jamie Turner at Bump.com.
