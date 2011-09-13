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
some buffer space for data in flight between frontend in backend.

`stud` has very few features--it's designed to be paired with an intelligent
backend like haproxy or nginx.  It maintains a strict 1:1 connection pattern
with this backend handler so that the backend can dictate throttling behavior,
maxmium connection behavior, availability of service, etc.

`stud` has one "cool trick"--it will optionally write the client IP address
as the first few octets (depending on IPv4 or IPv6) to the backend--or provide
that information using HAProxy's PROXY protocol.  In this way, backends
who care about the client IP can still access it even though `stud` itself
appears to be the connected client.

Thanks to a contribution from Emeric at Exceliance (the folks behind HAProxy),
a special build of `stud` can be made that utilitizes shared memory to
use a common session cache between all child processes.  This can speed up
large `stud` deployments by avoiding client renegotiation.

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

The entire set of arguments can be invoked with `stud -h`:

    Encryption Methods:
      --tls                    (TLSv1, default)
      --ssl                    (SSLv3)
      -c CIPHER_SUITE          (set allowed ciphers)

    Socket:
      -b HOST,PORT             (backend [connect], default "127.0.0.1,8000")
      -f HOST,PORT             (frontend [bind], default "*,8443")

    Performance:
      -n CORES                 (number of worker processes, default 1)
      -B BACKLOG               (set listen backlog size, default 100)
      -C SHARED_CACHE          (set shared cache size in sessions, by default no shared cache.
                               Only available if built with shared cache support)

    Security:
      -r PATH                  (chroot)
      -u USERNAME              (set gid/uid after binding the socket)

    Logging:
      -q                       (Be quiet. Emit only error messages)

    Special:
      --write-ip               (write 1 octet with the IP family followed by
                                4 (IPv4) or 16 (IPv6) octets little-endian
                                to backend before the actual data)
      --write-proxy            (write HaProxy's PROXY protocol line before actual data:
                                "PROXY TCP4 <source-ip> <dest-ip> <source-port> <dest-port>\r\n"
                                Note, that dest-ip and dest-port are initialized once after the socket
                                is bound. It means that you will get 0.0.0.0 as dest-ip instead of 
                                actual IP if that what the listening socket was bound to)

`stud` uses no configuration file.

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

    * Colin Percival @cperciva      -- early audit and code review
    * Frank DENIS @jedisct1         -- port to BSD, IPv6 support, various fixes
    * Denis Bilenko                 -- HAProxy PROXY protocol support, chroot/setuid
    * Joe Damato                    -- Diffie-Hellman parameter loading
    * Benjamin Pineau               -- Chained cert loading, various fixes
    * Carl Perry/Dreamhost          -- IPv6 PROXY support
    * Emeric Brun/Exceliance        -- Session resumption and shared-memory
                                       session cache
    * Vladimir Dronnikov            -- Logging cleanup
    * James Golick/BitLove Inc.     -- SIGPIPE fixes and child-reaping
