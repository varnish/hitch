
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

backend = ...
-------------

The endpoint Hitch connects to when receiving a connection. Only
a single backend is supported.

This is either specified as "[HOST]:port" for IPv4/IPv6 endpoints::

  backend = "[localhost]:8080"

Or it can be specified as a path to a UNIX domain socket::

  backend = "/path/to/sock"


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

Each cipher in the list must be separated by a colon (``:``), in order
of preference. See ``ciphers(1)`` for further description of the
format.

If not specified, OpenSSL will allow all ciphers. System
administrators are advised to either only support strong ciphers (as in
the example file below) or to pay close attention to security advisories
related OpenSSL's ciphers.

This option applies to TLSv1.2 and below. For TLSv1.3, see
``ciphersuites``.

This option is also available in frontend blocks.

ciphersuites = <string>
-----------------------

Specifies available ciphersuites for TLSv1.3. Similar to ``ciphers``,
entries must be separated by colon (``:``) and sorted in order of
preference.

This option is also available in frontend blocks.

client-verify = required|optional|none
--------------------------------------

Configures client certificate validation. The setting must be one of
``none``, ``required`` or ``optional``.

The default setting is ``client-verify = none``, in which case Hitch
will not send a certificate request to the client.

If ``client-verify = require`` is configured, Hitch will only permit
connections that present a valid certificate. The certificate will be
verified using the certificate provided in the ``client-verify-ca``
parameter.

If ``optional``, Hitch will send certificate requests, but still
permit connections that do not present one.

For settings ``optional`` and ``required``, we also require that the
``client-verify-ca`` is configured.

This option is also available in frontend blocks. If specified in a
frontend block, the client verification setting will only apply to the
``pem-file`` records for that particular frontend.

client-verify-ca = <string>
---------------------------

Specifies a file containing the certificates of the CAs that will be
used to verify a client certificate.

For multiple CAs, this file can be a concatenation of multiple
pem-files for the relevant certificate authorities.

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

backend-refresh = <number>
--------------------------

Number of seconds between periodic backend IP lookups, 0 to disable.
Default is 0.

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

ocsp-refresh-interval = <number>
--------------------------------

OCSP refresh interval.

If the OCSP response does not carry any refresh information, use this as the
interval for refreshing.

Default is 1800 seconds.

ocsp-verify-staple = on|off
---------------------------

If set, OCSP responses will be verified against the certificate
after retrieval.

Default is off.


pem-file = <string>
-------------------

Specify a SSL x509 certificate file. Server Name Indication (SNI) is
supported by using one certificate file per SNI name.

A file suitable for Hitch is a concatenation of a private key and a
corresponding certificate or certificate chain.

At least one PEM file is needed for Hitch to start, but it can be
supplied on the command line.

Certificates are used in the order they are listed; the last
certificate listed will be used if none of the others match.

In the event that we have multiple certificates that provide the same
SNI string, an error will be logged. The last loaded certificate will
in that case take precendence.

For partial overlap in names, e.g. if one certificate provides
"www.example.com" and another one "\*.example.com", the most specific
match will always take precendence at SNI lookup.

This option is also available in a frontend declaration, to make a
certificate only available for a specific listen endpoint.

private-key = <string>
----------------------

If set, the private key is read from specified location, not from the cert file.

::

   pem-file = {
       cert = "mycert.pem"
       private-key = "myprivate.key"
   }


pem-dir = <string>
------------------

Specify a directory for loading x509 certificates.

A fallback certificate for non-SNI clients may be specified by also
including a separate ``pem-file`` definition.

The files are processed in lexicographic order. In the absence of any
``pem-file`` definitions, the first file entry will be used as the
fallback default.

::
   
   pem-dir = "/etc/hitch/cert.d"


pem-dir-glob = <string>
-----------------------

Matching filter for filenames loaded from ``pem-dir``.

Default is none (match any).

::
   
  pem-dir-glob = "*.pem"


prefer-server-ciphers = on|off
------------------------------

Turns on or off enforcement of the cipher ordering set in Hitch.

This option is also available in frontend blocks.

Default is off.

proxy-proxy = on|off
--------------------

Proxy an incoming PROXY protocol header through to the
backend. Supports both version 1 and 2 of the PROXY protocol.

This option is mutually exclusive with option write-proxy-v2, write-ip
and write-proxy-v1.

Default is off.

log-level = <num>
-----------------

Log chattiness. 0=silence, 1=errors, 2=info/debug.

This setting can also be changed at run-time by editing the
configuration file followed by a reload (SIGHUP).

Default is 0.


quiet = on|off
--------------

If quiet is turned on, only error messages will be shown. This setting
is deprecated in favor of ``log-level``.


tls-protos = ...
----------------

The SSL/TLS protocols to be used. This is an unquoted list of
tokens. Available tokens are SSLv3, TLSv1.0, TLSv1.1, TLSv1.2 and
TLSv1.3.

The default is TLSv1.2 and TLSv1.3.

There are two deprecated options, ssl= and tls=, that also select
protocols. If "ssl=on" is used, then all protocols are selected. This
is known to be insecure, and is strongly discouraged. If "tls=on" is
used, the three TLS protocol versions will be used. Turning on SSLv3
and TLSv1.0 is not recommended - support for these protocols are only
kept for backwards compatibility.

The availability of protocol versions depend on OpenSSL version and
system configuration. In particular for TLS 1.3, openssl 1.1.1 or
later is required.

For supporting legacy protocol versions you may also need to lower the
``MinProtocol`` property in your OpenSSL configuration (typically
``/etc/ssl/openssl.cnf``).

This option is also available in frontend blocks.

ecdh-curve = <string>
~~~~~~~~~~~~~~~~~~~~~

Sets the list of supported TLS curves. A special value of ``auto``
will leave it up to OpenSSL to automatically pick the most appropriate
curve for a client.

::

   ecdh-curve = "X25519:prime256v1:secp384r1"


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

proxy-tlv = on|off
------------------

Report extra information as part of the PROXYv2 header.

Currently the following will be transmitted when proxy-tlv is enabled:

 - Cipher
 - Protocol version
 - Client certificate verification result
 - Whether the client transmitted a certificate as part of this
   connection/session (PP2_CLIENT_CERT_CONN, PP2_CLIENT_CERT_SESS)

Default is on.

proxy-client-cert = on|off
--------------------------

Transmit the authenticated client certificate as part of the PROXYv2
header.

The PEM-formatted client certificate will be transmitted as a TLV
field of type 0xe0.

This is a custom application-specific type, requiring a a custom
handler at the recipient end. Note that using this feature will
inflate the size of the PROXY header substantially, possibly also
requiring tweaking at the receiving end.


tcp-fastopen = on|off
---------------------

Enable TCP Fast Open.

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

    # We strongly recommend you create a separate non-privileged hitch
    # user and group
    user = "hitch"
    group = "hitch"

    # Enable to let clients negotiate HTTP/2 with ALPN. (default off)
    # alpn-protos = "h2, http/1.1"

    # run Varnish as backend over PROXY; varnishd -a :80 -a localhost:6086,PROXY ..
    write-proxy-v2 = on             # Write PROXY header


.. example-end

Author
======

This manual was written by Pål Hermunn Johansen <hermunn@varnish-software.com>
