# Virtual hosts

Running a virtual host setup behind Hitch works fine.

If you have reasonable clients (no XP/IE6, no older mobile), you can most likely
use a single `--frontend=` stance, and let the Server Name Indication (SNI) sent in the
handshake decide which certificate to present to the client.

*SNI example*:

	$ ./hitch --backend=example.com:80 \
		--frontend=[*]:443 \
		site1.example.com.pem site2.example.com.pem site3.example.com.pem

Hitch will automatically try to find the best matching certificate to give to the client. The last
PEM file provided will serve as the default if none of them matched. Wild-card certificates work fine,
any more specific certificate will be preferred over a wild-card match.

If you would rather close the connection than serve a certificate that will
yield a warning on the client, you can add the `--sni-nomatch-abort` argument.

To avoid the messy long command line with many certificates, you can use
multiple "pem-file = cert.pem" stances in a configuration file instead.

## Legacy clients

To support older clients, you need to add multiple `--frontend=` stances to your configuration
file (or command line) and a separate PEM file for each of them. Usually this
means that you need many IP addresses assigned to the hitch server as well.

*Legacy client example:*

	$ ./hitch --ssl --backend=example.com:80 \
		"--frontend=[192.0.2.10]:443+certs/site1.example.com" \
		"--frontend=[192.0.2.11]:443+certs/site2.example.com" \
        	certs/default.example.com

Remember that hitch is protocol agnostic. It does not know about HTTP, it only passes bytes back and
forth. In other words it will not set `X-Forwarded-Proto` or `X-Forwarded-For` on requests seen by the backend
server. The PROXY protocol support exists for signalling the real client IP to the backend.

