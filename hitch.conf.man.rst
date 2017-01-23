
.. _hitch.conf(5):

==========
Hitch.conf
==========

----------------------------
Configuration file for Hitch
----------------------------

:Manual section: 5

Description
===========

hitch.conf is the configuration file for `hitch(8)`. The configuration
file is loaded using the Hitch option --config=, and can thus have
different names and can exist in different locations.

Almost all options available in hitch.conf can be specified or
overridden in the command line of Hitch, as described in hitch(8).

The Hitch configuration file consists of a series of option
assignments.  Some options (pem-file, frontend) can be be set several
times, and the effect is that multiple certificate files and
"listening frontends" are defined. Other options can only be assigned
once.

The hash mark, or pound sign ("#"), is used as a "comment"
character. You can use it to annotate your config file. All text after
the comment character to the end of the line is ignored. Empty lines
are ignored.

Options
=======

Options can either be in the top level of the configuration file
(global scope), or inside a *frontend block*. Options inside a
frontend block only affect the frontend, while options in the top
level sets defaults for all frontends.

Unless otherwise noted below, options can only be used in the top
level.

alpn-protos = <protocol-list>
-----------------------------

Comma separated list of protocols supported by the backend in a quoted
string. The list is used select protocols when the client supports
Next Protocol Negotiation (NPN) or Application-Layer Protocol
Negotiation (ALPN). If Hitch is compiled against a OpenSSL version
that does not support ALPN, only NPN will be used to select a
protocol.

The result of the NPN/ALPN negotiation will be communicated to the
backend if and only if write-proxy-v2 or proxy-proxy is used. For
HTTP/2 to work with modern browsers, ALPN negotiation is required.

backend = "[HOST]:PORT"
-----------------------

The host and port Hitch connects to when receiving a connection. Only
a single backend is supported.

backlog = <number>
------------------

Listen backlog size

chroot = <string>
-----------------

Chroot directory

ciphers = ...
-------------

List of ciphers to use in the secure communication. Refer to the
OpenSSL documentation for a complete list of supported ciphers.

If not specified, OpenSSL will allow all ciphers. System
administrators are advised to either only support strong ciphers (as in
the example file below) or to pay close attention to security advisories
related OpenSSL's ciphers.

This option is also available in frontend blocks.

daemon = on|off
---------------

Run as daemon. Default is off.

frontend = ...
--------------

This specifies the port and interface (the *listen endpoint*) that
Hitch binds to when listening for connections. It is possible define
several frontends, and Hitch will bind to several ports and/or several
interfaces.

If "*" is used as the host, then Hitch will bind on all interfaces for
the given port.

A frontend can be specified either in a single line:

::

    frontend = "[HOST]:PORT[+CERT]"

Or in a *frontend block*:

::

    frontend = {
        host = "HOST"
        port = "PORT"
        <other frontend options>
    }

group = <string>
----------------

If given, Hitch will change to this group after binding to listen
sockets.

keepalive = <number>
--------------------

Number of seconds a TCP socket is kept alive

ocsp-dir = <string>
-------------------

Directory where Hitch will store and read OCSP responses for
stapling. Default is "/var/lib/hitch/".

Directory must be readable and writable for the configured Hitch user, or
automatic retrieval and updating of OCSP responses will not take place.

If you have a manually pre-loaded OCSP staple, an alternative
pem-file syntax can be used for stapling:

::

   pem-file = {
       cert = "mycert.pem"
       ocsp-resp-file = "ocsp-resp.der"
   }


ocsp-connect-tmo = <number>
---------------------------

OCSP fetch connect timeout.

This does normally not need to be changed.

Default is 4.0 seconds.


ocsp-resp-tmo = <number>
------------------------

OCSP fetch response timeout.

This does normally not need to be changed.

Default is 10 seconds.


ocsp-verify-staple = on|off
---------------------------

If set, OCSP responses will be verified against the certificate
after retrieval.

Default is off.


pem-file = <string>
-------------------

Specify a SSL x509 certificate file. Server Name Indication (SNI) is
supported by using one certificate file per SNI name.

Certificates are used in the order they are listed; the last
certificate listed will be used if none of the others match.

A file suitable for Hitch is a concatenation of a private key and a
corresponding certificate or certificate chain.

At least one PEM file is needed for Hitch to start, but it can be
supplied on the command line.

This option is also available in a frontend declaration, to make a
certificate only available for a specific listen endpoint.

prefer-server-ciphers = on|off
------------------------------

Turns on or off enforcement of the cipher ordering set in Hitch.

This option is also available in frontend blocks.

Default is off.

proxy-proxy = on|off
--------------------

Proxy an existing PROXY protocol header through this request. At the
moment this is equivalent to write-proxy-v2.

This option is mutually exclusive with option write-proxy-v2, write-ip
and write-proxy-v1.

Default is off.

quiet = on|off
--------------

If quiet is turned on, only error messages will be shown.

tls-protos = ...
----------------

The SSL/TLS protocols to be used. This is an unquoted list of
tokens. Available tokens are SSLv3, TLSv1.0, TLSv1.1 and TLSv1.2.

The default is TLSv1.1 and TLSv1.2.

There are two deprecated options, ssl= and tls=, that also select
protocols. If "ssl=on" is used, then all protocols are selected. This
is known to be insecure, and is strongly discouraged. If "tls=on" is
used, the three TLS protocol versions will be used. Turning on SSLv3
and TLSv1.0 is not recommended - support for these protocols are only
kept for backwards compatibility.

This option is also available in frontend blocks.

sni-nomatch-abort = on|off
--------------------------

Abort handshake when the client submits an unrecognized SNI server name.

This option is also available in a frontend declaration.

ssl-engine = <string>
---------------------

Set the SSL engine. This is used with SSL accelerator cards. See the
OpenSSL documentation for legal values.

syslog = on|off
----------------

Send messages to syslog. Default is off.

syslog-facility = <string>
--------------------------

Set the syslog facility. Default is "daemon".

user = <string>
---------------

User to run as. If Hitch is started as root, it will insist on
changing to a user with lower rights after binding to sockets.

workers = <number>
------------------

Number of worker processes. One per CPU core is recommended.

write-ip = on|off
-----------------

Report the client ip to the backend by writing IP before sending
data.

This option is mutually exclusive with each of the options
write-proxy-v2, write-proxy-v1 and proxy-proxy.

Default is off.

write-proxy-v1 = on|off
-----------------------

Report client address using the PROXY protocol.

This option is mutually exclusive with option write-proxy-v2, write-ip
and proxy-proxy.

Default is off.

write-proxy-v2 = on|off
-----------------------

Report client address using PROXY v2 protocol.

This option is mutually exclusive with option write-ip, write-proxy-v1
and proxy-proxy.

Default is off.

Example
=======

.. example-start

The following file shows the syntax needed to get started with::

    frontend = {
        host = "*"
        port = "443"
    }
    backend = "[127.0.0.1]:6086"    # 6086 is the default Varnish PROXY port.
    workers = 4                     # number of CPU cores

    daemon = on
    user = "nobody"
    group = "nogroup"

    # Enable to let clients negotiate HTTP/2 with ALPN. (default off)
    # alpn-protos = "http/2, http/1.1"

    # run Varnish as backend over PROXY; varnishd -a :80 -a localhost:6086,PROXY ..
    write-proxy-v2 = on             # Write PROXY header


.. example-end

Author
======

This manual was written by Pål Hermunn Johansen <hermunn@varnish-software.com>
