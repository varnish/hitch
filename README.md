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
using HAProxy's PROXY protocol.  In this way, backends who care about the
client IP can still access it even though `stud` itself appears to be the
connected client.

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
 * `stud` has optional builds that utilize shared memory-based SSL contexts
   to keep a session cache between many child processes.  The use of these
   builds can dramatically speed up SSL handshakes on many-core deployments.
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
(or a chain of certificates) and private key.

Detail about the entire set of options can be found by invoking `stud -h`:

    Encryption Methods:
      --tls                    TLSv1 (default)
      --ssl                    SSLv3 (implies no TLSv1)
      -c CIPHER_SUITE          set allowed ciphers (default is OpenSSL defaults)
      -e ENGINE                set OpenSSL engine

    Socket:
      -b HOST,PORT             backend [connect] (default is "127.0.0.1,8000")
      -f HOST,PORT             frontend [bind] (default is "*,8443")

    Performance:
      -n CORES                 number of worker processes (default is 1)
      -B BACKLOG               set listen backlog size (default is 100)

    Security:
      -r PATH                  chroot
      -u USERNAME              set gid/uid after binding the socket

    Logging:
      -q                       be quiet; emit only error messages
      -s                       send log message to syslog in addition to stderr/stdout

    Special:
      --write-ip               write 1 octet with the IP family followed by the IP
                               address in 4 (IPv4) or 16 (IPv6) octets little-endian
                               to backend before the actual data
      --write-proxy            write HaProxy's PROXY (IPv4 or IPv6) protocol line
                               before actual data

`stud` uses no configuration file.

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
by the Bump (http://bu.mp) server team.  It currently (6/11) provides
server-side TLS termination for over 40 million Bump users.

Contributors:

    * Colin Percival @cperciva      -- early security audit and code review
    * Frank DENIS @jedisct1         -- port to BSD, IPv6 support, various fixes
    * Denis Bilenko                 -- HAProxy PROXY protocol support, chroot/setuid
    * Joe Damato                    -- Diffie-Hellman parameter loading
    * Benjamin Pineau               -- Chained cert loading, various fixes,
                                       performance tweaks
    * Carl Perry/Dreamhost          -- IPv6 PROXY support
    * Emeric Brun/Exceliance        -- Session resumption and shared-memory
                                       session cache
    * Vladimir Dronnikov            -- Logging cleanup
    * James Golick/BitLove Inc.     -- SIGPIPE fixes and child-reaping
    * Joe Williams                  -- Syslog support
    * Jason Cook                    -- SSL option tweaks (performance)
    * Artur Bergman                 -- Socket tweaks (performance)
