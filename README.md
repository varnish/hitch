hitch TLS proxy
===============

[![CircleCI Build Status](https://circleci.com/gh/varnish/hitch/tree/master.svg?style=svg)](https://circleci.com/gh/varnish/hitch/tree/master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/5137/badge.svg)](https://scan.coverity.com/projects/hitch)

`hitch` is a network proxy that terminates TLS/SSL connections and forwards the
unencrypted traffic to some backend. It's designed to handle 10s of thousands of
connections efficiently on multicore machines.

See the [web page](https://hitch-tls.org) for more information.
