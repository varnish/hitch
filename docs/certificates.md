# Creating a SSL/TLS key and certificate

The minimum requirement for hitch to work is a PEM file with:

  - an RSA key
  - a certificate
  - (if you are doing DH ciphers: Diffie-Hellman parameters)

For production use, you probably want to buy one from a friendly Certificate
Authority (CA) nearby. For testing/playing around with hitch, you can create one using openssl:

    $ openssl req -newkey rsa:2048 -sha256 -keyout example.com.key -nodes -x509 -days 365 -out example.crt

This will write a key file and the self-signed certificate for it.

The normal steps of writing a Certificate Signing Request and so on isn't necessary for self-signed certificates.

To complete this chain you merge the files into a single PEM file that you give hitch:


    $ cat example.com.key example.crt > example.pem


And then start Hitch:

  $ hitch --backend=[127.0.0.1]:80 example.pem

and you're done!

If you are running on a Debian system, there is a shell script available to simplify this in the _ssl-cert_ package: `make-ssl-cert /usr/share/ssl-cert/ssleay.cnf /etc/hitch/testcert.pem`

On Redhat systems the OpenSSL package has `/etc/pki/tls/certs/make-dummy-cert` that can be used.

If you want to use Diffie-Hellman ciphers for Forward Secrecy, you need to add
a bit of randomness to your PEM file as well. How you do this is described in [configuration](configuration.md).
