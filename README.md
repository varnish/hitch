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

`stud` has one "cool trick"--it will optionally write the client IPv4 address
as the first four octets little endian.  In this way, backends who care about
the client IP can still access it even though `stud` itself appears to be
the connected client.

Requirements and Limitations
----------------------------

`stud` requires:

    libev >= 4
    openssl (recent, >=1.0.0 recommended)

Stud currently works on Linux, OpenBSD and MacOSX.

While porting it to other POSIX platforms is likely trivial, it hasn't be done
yet. Patches welcome!

If you're handling a large number of connections, you'll
probably want to raise `ulimit -n` before running `stud`.

Installing
----------

To install `stud`:

    $ make
    $ sudo make install

Usage
-----

The only required argument is a path to a PEM file that contains the certificate
and private key.

The entire set of arguments can be invoked with `stud -h`:

    Encryption Methods:
      --tls                    (TLSv1, default)
      --ssl                    (SSLv3)

    Socket:
      -b HOST,PORT             (backend [connect], default "127.0.0.1,8000")
      -f HOST,PORT             (frontend [bind], default "*,8443")

    Performance:
      -n CORES                 (number of worker processes, default 1)

    Special:
      --write-ipv4             (write remote IPv4 in first 4 octets
                                little-endian to backend)

`stud` uses no configuration file.

Authors
-------

`stud` was initially written by Jamie Turner <jamie@bu.mp> and is maintained
by the Bump server team.  It currently (6/11) provides server-side TLS
termination for over 40 million Bump users.
