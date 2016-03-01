# Hitch architecture

Hitch uses a process-per-core model; a parent process spawns N children who
each `accept()` on a common socket to distribute connected clients among them.

Within each child, asynchronous socket I/O is conducted across the local
connections using `libev` and `OpenSSL`'s nonblocking API. By default,
`hitch` has an overhead of ~200KB per connection--it preallocates
some buffer space for data in flight between frontend and backend.

`hitch` has very few features--it's designed to be paired with an intelligent
backend like Varnish Cache. It maintains a strict 1:1 connection pattern
with this backend handler so that the backend can dictate throttling behavior,
maximum connection behavior, availability of service, etc.


