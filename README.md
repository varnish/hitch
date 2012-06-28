stud - The Scalable TLS Unwrapping Daemon
=========================================

`stud` is a network proxy that terminates TLS/SSL connections and forwards the
unencrypted traffic to some backend.  It's designed to handle 10s of thousands of
connections efficiently on multicore machines.

It follows a process-per-core model; a parent process spawns N children who
each `accept()` on a common socket to distribute connected clients among them.
Within each child, asynchronous socket I/O is conducted across the local
connections using `libev` and `OpenSSL`'s nonblocking API.  By default,
`stud` has an overhead of ~200KB per connection--it preallocates
some buffer space for data in flight between frontend and backend.

`stud` has very few features--it's designed to be paired with an intelligent
backend like haproxy or nginx.  It maintains a strict 1:1 connection pattern
with this backend handler so that the backend can dictate throttling behavior,
maxmium connection behavior, availability of service, etc.

`stud` will optionally write the client IP address as the first few octets
(depending on IPv4 or IPv6) to the backend--or provide that information
using HAProxy's PROXY protocol.  When used with the PROXY protocol, `stud` can
also transparently pass an existing PROXY header to the cleartext stream.  This
is especially useful if a TCP proxy is used in front of `stud`.  Using either of
these techniques, backends who care about the client IP can still access it even
though `stud` itself appears to be the connected client.

Thanks to a contribution from Emeric at Exceliance (the folks behind HAProxy),
a special build of `stud` can be made that utilitizes shared memory to
use a common session cache between all child processes.  This can speed up
large `stud` deployments by avoiding client renegotiation.

Releases
---------

Please be aware of the policy regarding releases, code stability, and security:

 * In git, the tip of the master branch should always build on Linux and
   FreeBSD, and is likely to be as stable as any other changeset.  A
   careful review of patches is conducted before being pushed to github.
 * Periodically, a version tag will be pushed to github for an old(er)
   changeset--0.1, 0.2, etc.  These tags mark a particular release of
   `stud` that has seen heavy testing and several weeks of production
   stability.  Conservative users are advised to use a tag.
 * `stud` has an optional build that utilizes shared memory-based SSL contexts
   and UDP peer communication to keep a session cache between many child processes
   running on many machines.  The use of this build can dramatically speed
   up SSL handshakes on many-core and/or clustered deployments.
   However, it's important to acknowledge the inevitable theoretical
   security tradeoffs associated with the use of this (substantially more
   complex) binary.  Therefore, the deeply paranoid are advised to use
   only the standard `stud` binary at the cost of some performance.

Requirements and Limitations
----------------------------

`stud` requires:

    libev >= 4
    openssl (recent, >=1.0.0 recommended)

Stud currently works on Linux, OpenBSD, FreeBSD, and MacOSX.
It has been tested the most heavily on Linux/x86_64.

While porting it to other POSIX platforms is likely trivial, it hasn't be done
yet. Patches welcome!

If you're handling a large number of connections, you'll
probably want to raise `ulimit -n` before running `stud`.
It's very strongly recommended to not run `stud` as root; ideally, it would
be run as a user ("stud", perhaps) that does nothing but run `stud`.  Stud
will setuid (using -u) after binding if you need to bind to a low port (< 1024).

Installing
----------

To install `stud`:

    $ make
    $ sudo make install

Usage
-----

The only required argument is a path to a PEM file that contains the certificate
(or a chain of certificates) and private key. If multiple certificates are
given, `stud` will attempt to perform SNI (Server Name Indication) on new
connections, by comparing the indicated name with the names on each of the
certificates, in order. The first certificate that matches will be used. If none
of the certificates matches, the last certificate will be used as the default.

Detail about the entire set of options can be found by invoking `stud -h`:

    CONFIGURATION:

            --config=FILE      Load configuration from specified file.
            --default-config   Prints default configuration to stdout.

    ENCRYPTION METHODS:

          --tls                   TLSv1 (default)
          --ssl                   SSLv3 (implies no TLSv1)
      -c  --ciphers=SUITE         Sets allowed ciphers (Default: "")
      -e  --ssl-engine=NAME       Sets OpenSSL engine (Default: "")
      -O  --prefer-server-ciphers Prefer server list order

    SOCKET:

      -b  --backend=HOST,PORT     Backend [connect] (default is "[127.0.0.1]:8000")
      -f  --frontend=HOST,PORT    Frontend [bind] (default is "[*]:8443")

    PERFORMANCE:

      -n  --workers=NUM          Number of worker processes (Default: 1)
      -B  --backlog=NUM          Set listen backlog size (Default: 100)
      -k  --keepalive=SECS       TCP keepalive on client socket (Default: 3600)

    SECURITY:

      -r  --chroot=DIR           Sets chroot directory (Default: "")
      -u  --user=USER            Set uid/gid after binding the socket (Default: "")
      -g  --group=GROUP          Set gid after binding the socket (Default: "")

    LOGGING:
      -q  --quiet                Be quiet; emit only error messages
      -s  --syslog               Send log message to syslog in addition to stderr/stdout
      --syslog-facility=FACILITY Syslog facility to use (Default: "daemon")

    OTHER OPTIONS:
          --daemon               Fork into background and become a daemon (Default: off)
          --write-ip             Write 1 octet with the IP family followed by the IP
                                 address in 4 (IPv4) or 16 (IPv6) octets little-endian
                                 to backend before the actual data
                                 (Default: off)
          --write-proxy          Write HaProxy's PROXY (IPv4 or IPv6) protocol line
                                 before actual data
                                 (Default: off)
          --proxy-proxy          Proxy HaProxy's PROXY (IPv4 or IPv6) protocol line
                                 before actual data
                                 (Default: off)

      -t  --test                 Test configuration and exit
      -V  --version              Print program version and exit
      -h  --help                 This help message

Configuration File
------------------

Stud can also use a configuration file that supports all the same options as the
command-line arguments. You can use `stud --default-config` to
generate the default configuration on stdout; then, customize your configuration and
pass it to `stud --config=FILE`.

Serving HTTPS
-------------

If you're using `stud` for HTTPS, please make sure to use the `--ssl` option!


Diffie–Hellman
--------------

To use DH with stud, you will need to add some bytes to your pem file:

% openssl dhparam -rand - 1024 >> PEMFILE

Be sure to set your cipher suite appropriately: -c DHE-RSA-AES256-SHA

Authors
-------

`stud` was originally written by Jamie Turner (@jamwt) and is maintained
by the Bump (http://bu.mp) server team.  It currently (12/11) provides
server-side TLS termination for over 85 million Bump users.

Special thanks to Colin Percival (@cperciva) for an early security
audit and code review.

Finally, thank you to all the stud contributors, who have taken the
program from a good start to a solid project:

https://github.com/bumptech/stud/contributors
