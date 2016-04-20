List of changes
===============

This file contains the running log of changes applied to each released hitch
version.

hitch-1.2.0 (2016-04-19)
------------------------

* Fixes two minor leaks discovered by Coverity
* #72: Fix a error handling for command line --frontend option.
* Various autotools improvements
* Parallel make check

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
* #55: Fix a bug which caused the Hitch worker threads to sometimes
  hit an assert after a configuration reload.
* #57: Slightly reorganize assertion handling.
* #52: Fix a bug where we would crash on --help.
* Various minor documentation changes.


hitch-1.1.0 (2015-11-20)
------------------------

* Avoid leaking memory if failing to create an ssl context. (coverity)
* Fix possible memory leak in create_listen_sock(). (coverity)


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

* #37: Fixes a bug related to a varargs buffer that was consumed twice
  with syslog logging enabled.
* --default-config retired and replaced by shipping a sample configuration file.
* Use accept4() where supported.
* --write-proxy now defaults to PROXY v2. This is a BREAKING CHANGE if PROXY1
  is used. For PROXY v1, use --write-proxy-v1 explicitly.
* Various minor error handling fixes.


hitch 1.0.0-beta4 (2015-07-08)
------------------------------

In general beta4 contains fixes to problems found with Coverity. These
were all of minor character, but were fixed for completeness.

Source code has been reindented from 3-4 different formatting
styles to FreeBSD style.


hitch 1.0.0-beta3 (2015-06-18)
------------------------------

* Drop supplementary groups when doing setgid(). (github issue #31)
* Add --sni-nomatch-abort which abort connections on unknown SNI server
  name. (useful for avoiding certificate warnings in clients attempting
  probabilistic TLS upgrades)
* Remove cosmetic NULL-check before free(). (github issue #26)
* Avoid segfault when testing configuration with -t. (github issue #22)
* Minor helptext changes.


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

