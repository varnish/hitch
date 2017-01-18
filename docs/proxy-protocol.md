# PROXY protocol

PROXY protocol allows hitch to send a short header/message just before the main
connection data on the backend connection.

The short header describes which IP address and port was used to connect to
the proxy (Hitch), and which IP address and port was connected to. The last
one is useful if Hitch is listening to more than one IP or port.

The PROXY protocol was specified by Willy Tarreau of HAProxy
Technologies [1] and exists in two different versions: PROXY1 which is
a simple text header, and PROXY2 which is a binary representation
(default). Hitch supports both through the global `--write-proxy-v1`
and `--write-proxy-v2` configuration keys.

Backend servers that support PROXY will read this first and most likely use
it instead of the Hitch IP/port for when writing access logs. If Hitch is
running on the same machine, the logs would otherwise use "127.0.0.1" which
isn't very useful.

The upside of using PROXY is that we don't need to know the protocol we're
proxying. For HTTP the alternative is to add to X-Forwarded-For, which means
we need to understand what HTTP headers are, how they are formatted, how to move
the remaining bytes around when adding our content, and so on.  By using PROXY
we don't have to program that logic into Hitch, and we don't take the
performance penalty of doing string search and replace in the bytes we proxy.



[1]: http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
