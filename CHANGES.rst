List of changes
===============

This file contains the running log of changes applied to each released hitch
version.

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

