List of changes
===============

This file contains the running log of changes applied to each released hitch
version.

hitch-1.4.6 (2017-06-06)
------------------------

* Fix a problem that broke mock-based builds for el6/el7 (Issue 181_)

.. _181:  https://github.com/varnish/hitch/issues/181


hitch-1.4.5 (2017-05-31)
------------------------

* Set SSL_OP_SINGLE_ECDH_USE to force a fresh ECDH key pair per
  handshake (Issue 155_)
* Fix a bug where we ended up leaking a zombie process on reload
  (Issue 167_). Thank you to @dward
* Fix a bug where the management process could not find its
  configuration files after a reload when chroot was configured (Issue 176_)
* Output the offending line on a configuration file parsing error
* Fix build for non-C99/C11 compilers (Issue 173_)
* Fix the shared cache code to make it work also with OpenSSL 1.1.0
* Fix an unchecked loop situation that could occur when running
  with shared cache enabled (Issue 152_)
* Various autotools configuration fixes
* A few minor doc fixes

.. _155: https://github.com/varnish/hitch/issues/155
.. _167: https://github.com/varnish/hitch/issues/167
.. _176: https://github.com/varnish/hitch/issues/176
.. _173: https://github.com/varnish/hitch/issues/173
.. _152: https://github.com/varnish/hitch/issues/152


hitch-1.4.4 (2016-12-22)
------------------------

* OpenSSL 1.1.0 compatibility fixes. OpenSSL 1.1.0 is now fully
  supported with Hitch.
* Fix a bug in the OCSP refresh code that could make it loop with
  immediate refreshes flooding an OCSP responder.
* Force the SSL_OP_SINGLE_DH_USE setting. This protects against an
  OpenSSL vulnerability where a remote attacker could discover private
  DH exponents (CVE-2016-0701).


hitch-1.4.3 (2016-11-14)
------------------------

* OCSP stapling is now enabled by default.
  Users should create ocsp-dir (default: /var/lib/hitch/) and make it
  writable for the hitch user.

* Build error due to man page generation on FreeBSD (most likely non-Linux)
  has been fixed.


hitch-1.4.2 (2016-11-08)
------------------------

* Example configuration file hitch.conf.example has been shortened and
  defaults moved into Hitch itself. Default cipher string is now what we
  believe to be secure. Users are recommended to use the built-in default
  from now on, unless they have special requirements.

* hitch.conf(5) manual has been added.

* Hitch will now send a TLS Close notification during connection teardown.
  This fixes an incomplete read with a GnuTLS client when the backend
  (thttpd) used EOF to signal end of data, leaving some octets discarded
  by gnutls client-side. (Issue 127_)

* Autotools will now detect SO_REUSEPORT availability. (Issue 122_)

* Improved error handling on memory allocation failure.

.. _122: https://github.com/varnish/hitch/issues/122
.. _127: https://github.com/varnish/hitch/issues/127


hitch-1.4.1 (2016-09-23)
------------------------

* Add a new ``tls-protos`` configuration option for specifying the
  permitted TLS/SSL protocols. This new option supersedes settings
  ``ssl`` and ``tls`` which are now deprecated and will be kept for
  backwards compatibility.


hitch-1.4.0 (2016-09-12)
------------------------

* Fix a bug in the OCSP request code where it broke if the OCSP
  responder required a Host header. (Issue 113_)

* Add support for ECC certificates. (Issue 116_)

.. _113: https://github.com/varnish/hitch/issues/113
.. _116: https://github.com/varnish/hitch/issues/116


hitch-1.4.0-beta1 (2016-08-26)
------------------------------

* NPN/ALPN support for negotiating a protocol in the SSL
  handshake. This lets you use Hitch for terminating TLS in front of
  an HTTP/2 capable backend. For ALPN, OpenSSL 1.0.2 is needed, while
  NPN requires OpenSSL 1.0.1.

* Expanded PROXY protocol support for communicating an ALPN/NPN
  negotiated protocol to the backend. Hitch will now include the
  ALPN/NPN protocol that was selected during the handshake as part of
  the PROXYv2 header.


hitch-1.3.1 (2016-08-16)
------------------------

* Fixes a bug in the autotools configuration which led to man pages not being built.


hitch-1.3.0 (2016-08-16)
------------------------

* Fix a bug where we crashed in the OCSP handling if there was no
  default SSLCTX configured.

* Minor documentation fix.


hitch-1.3.0-beta3 (2016-07-26)
------------------------------

* Fully automated retrieval and refreshes of OCSP responses (see
  configuration.md for details).
* New parameters ``ocsp-dir``, ``ocsp-resp-tmo`` and ``ocsp-connect-tmo``.
* Cleanup of various log messages.
* Verification of OCSP staples. Enabled by setting
  ``ocsp-verify-staple = on``.
* Make rst2man an optional requirement (Issue 93_). Thanks to Barry Allard.
* Avoid stapling expired OCSP responses.
* A few fixes to the shared cache updating code. Thanks to Piyush Dewnani.

.. _93: https://github.com/varnish/hitch/issues/93

hitch-1.3.0-beta2 (2016-05-31)
------------------------------

* Options given on the command line now take presedence over
  configuration file settings. I.e. there is no longer a need to
  specify ``--config`` first to get this behavior.
* Config file regression: "yes" and "no" are now accepted by the
  config file parser as boolean values.
* Documentation improvements and spelling fixes.
* Various minor autotools build fixes.

hitch-1.3.0-beta1 (2016-05-11)
------------------------------

* Support for OCSP stapling (see configuration.md for details)
* Initialize OpenSSL locking callback if an engine is loaded. Some SSL
  accelerator cards have their custom SSL engine running in a
  multithreaded context. For these to work correctly, Hitch needs to
  initialize a set of mutexes utilized by the OpenSSL library.
* Issue 82_: A mistake in the SNI lookup code caused us to inspect the wrong
  list when looking for wildcard certificate matches.

.. _82: https://github.com/varnish/hitch/issues/82


hitch-1.2.0 (2016-04-19)
------------------------

* Fixes two minor leaks discovered by Coverity
* Issue 72_: Fix a error handling for command line --frontend option.
* Various autotools improvements
* Parallel make check

.. _72: https://github.com/varnish/hitch/issues/72


hitch-1.2.0-beta1 (2016-02-25)
------------------------------

* Expanded configuration file format to permit settings various
  options at a more granular level.
* The following options can now be set on a per-frontend basis:
  ``pem-file``, ``ssl``, ``tls``, ``ciphers``,
  ``prefer-server-ciphers``, ``sni-nomatch-abort``
* Added options ``host`` and ``port`` for specifying the listening
  endpoint in a ``frontend`` block.
* Added option ``match-global-certs`` (available in a ``frontend``
  declaration)


hitch-1.1.1 (2016-01-26)
------------------------

* Remove compiler warning on FreeBSD.
* Fix fatal build error for manpage on FreeBSD.
* Issue 55_: Fix a bug which caused the Hitch worker threads to sometimes
  hit an assert after a configuration reload.
* Issue 57_: Slightly reorganize assertion handling.
* Issue 52_: Fix a bug where we would crash on --help.
* Various minor documentation changes.

.. _57: https://github.com/varnish/hitch/issues/57
.. _55: https://github.com/varnish/hitch/issues/55
.. _52: https://github.com/varnish/hitch/issues/52


hitch-1.1.0 (2015-11-20)
------------------------

* Avoid leaking memory if failing to create an SSL context. (Coverity)
* Fix possible memory leak in create_listen_sock(). (Coverity)


hitch-1.1.0-beta1 (2015-11-06)
------------------------------

* [dist] init.hitch file has been removed, CHANGES.rst is now distributed.
* [configure] session cache support can now be enabled. (default off)
* Fixes an off-by-one bug that broke wildcard certificate matching.
* Set the IPV6_V6ONLY socket option for IPv6 listen sockets in order
  to avoid conflicts between INADDR_ANY and IN6ADDR_ANY.
* Uninterrupted configuration reload of PEM files and frontend listen
  endpoints.
* Priv-sep: To permit configuration reloads, privileges are now
  dropped in the child processes, and elevated privileges are retained
  in the management process.
* Various error messages are now rewritten to be more specific about
  what went wrong.
* A warning is issued if multiple certificates contain identical
  server name entries.
* Initialize ECDH also for certificates without DH parameters (patch
  from Fedor Indutny).


hitch-1.0.1 (2015-10-15)
------------------------

* Fix configuration parsing bug skipping short values, typically "workers = 1".
* Tarball now contains an example configuration file.


hitch-1.0.0 (2015-10-07)
------------------------

* A hash table is now used for faster SNI lookups.
* Hitch binary has been renamed back to `hitch`, previously `hitch-openssl`.
* Man page is updated.


hitch-1.0.0-beta5 (2015-08-17)
------------------------------

* Issue 37_: Fixes a bug related to a varargs buffer that was consumed twice
  with syslog logging enabled.
* --default-config retired and replaced by shipping a sample configuration file.
* Use accept4() where supported.
* --write-proxy now defaults to PROXY v2. This is a BREAKING CHANGE if PROXY1
  is used. For PROXY v1, use --write-proxy-v1 explicitly.
* Various minor error handling fixes.

.. _37: https://github.com/varnish/hitch/issues/37


hitch 1.0.0-beta4 (2015-07-08)
------------------------------

In general beta4 contains fixes to problems found with Coverity. These
were all of minor character, but were fixed for completeness.

Source code has been reindented from 3-4 different formatting
styles to FreeBSD style.


hitch 1.0.0-beta3 (2015-06-18)
------------------------------

* Drop supplementary groups when doing setgid(). (Issue 31_)
* Add --sni-nomatch-abort which abort connections on unknown SNI server
  name. (useful for avoiding certificate warnings in clients attempting
  probabilistic TLS upgrades)
* Remove cosmetic NULL-check before free(). (Issue 26_)
* Avoid segfault when testing configuration with -t. (Issue 22_)
* Minor helptext changes.

.. _31: https://github.com/varnish/hitch/issues/31
.. _26: https://github.com/varnish/hitch/issues/26
.. _22: https://github.com/varnish/hitch/issues/22


hitch 1.0.0-beta2 (2015-05-22)
------------------------------

* New --pidfile argument.
* Fixed bug in certificate ordering, avoiding wrong cert being provided when
  running on dualstack servers. (found by test framework!)
* Rudimentary test framework implemented.
* Init script updates provided by Denis Brækhus.
* FreeBSD installation instructions added. (contributed by Ryan Steinmetz)
* autoconf configuration updated to work on EL6.
* Some forgotten references to stud were updated.


hitch 1.0.0-beta1 (2015-05-13)
------------------------------

Hitch 1.0.0-beta1 is based on stud 0.3.2. A selected set of public patches from
github forks were applied.

Notable changes:

* TLS v1.0, TLS v1.1 and TLS v1.2 support.
* Support for SNI added.
* Support PROXYv1 and PROXYv2 protocol to origin.
* Multiple listening sockets with possibly different default key/certificate.
* Wildcard certificates are supported. (with and without SNI.)
* SSL3.0 must now be enabled explicitly.


Various minor and stylistic fixed issues:

* Properly clean SSL error queue.
* Do not segfault if backend is not ready.
* Logging now knows about IPv6.
* IPv6 adresses should now use bracketed notation.
* Additional timeouts for backend connect and SSL handshake added.
* autoconf/automake is now used for building hitch.

