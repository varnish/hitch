# Installing hitch

`hitch` requires:

    libev >= 4
    openssl (recent, >=1.0.0 recommended)

hitch currently works on Linux, OpenBSD, FreeBSD, and MacOSX.
It has been tested the most heavily on Linux/x86_64.

## Installing from source

Install prerequisites on Debian based systems:

    $ sudo apt-get install libev-dev libssl-dev automake python-docutils flex bison pkg-config

To install `hitch`:

    $ ./bootstrap   # if running from git
    $ ./configure
    $ make
    $ sudo make install

This will install Hitch to /usr/local/, unless you override the destination
with ./configure --prefix=/foo (as usual)


## Installing from packages

``FreeBSD``

From packages:

    $ pkg install hitch

From ports:

    $ cd /usr/ports/security/hitch && make install clean


## Init scripts

Initialization scripts to start hitch automatically can be found in the
[wiki](https://github.com/varnish/hitch/wiki).

