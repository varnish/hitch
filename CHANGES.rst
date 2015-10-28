List of changes
===============

This file contains the running log of changes applied to each released hitch
version.


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

