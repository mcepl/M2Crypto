:orphan:

.. _howto-ssl:

HOWTO: Programming SSL in Python with M2Crypto
==============================================

:author: Pheng Siong Ng <ngps@netmemetic.com> and Heikki Toivonen (heikki@osafoundation.org)
:copyright: © 2000, 2001 by Ng Pheng Siong,
            portions © 2006 by Open Source Applications Foundation

Introduction
============

`M2Crypto <https://gitlab.com/m2crypto/m2crypto/>`__ is a
`Python <http://www.python.org>`__ interface to
`OpenSSL <http://www.openssl.org>`__. It makes available to the Python
programmer SSL functionality to implement clients and servers, S/MIME
v2, RSA, DSA, DH, symmetric ciphers, message digests and HMACs.

This document demonstrates programming HTTPS with M2Crypto.

A bit of history
================

M2Crypto was created during the time of Python 1.5, which features a
module httplib providing client-side HTTP functionality. M2Crypto sports
a httpslib based on httplib.

Beginning with version 2.0, Python's socket module provided
(rudimentary) SSL support. Also in the same version, httplib was
enhanced with class HTTPConnection, which is more sophisticated than the
old class HTTP, and HTTPSConnection, which does HTTPS.

Subsequently, M2Crypto.httpslib grew a compatible (but not identical)
class HTTPSConnection.

The primary interface difference between the two HTTPSConnection classes
is that M2Crypto's version accepts an M2Crypto.SSL.Context instance as a
parameter, whereas Python 2.x's SSL support does not permit Pythonic
control of the SSL context.

Within the implementations, Python's ``HTTPSConnection`` employs a
``FakeSocket`` object, which collects all input from the SSL connection
before returning it to the application as a ``StringIO`` buffer, whereas
M2Crypto's ``HTTPSConnection`` uses a buffering
``M2Crypto.BIO.IOBuffer`` object that works over the underlying
M2Crypto.SSL.Connection directly.

Since then M2Crypto has gained a Twisted wrapper that allows securing
Twisted SSL connections with M2Crypto.

Secure SSL
==========

It is recommended that you read the book Network Security with OpenSSL
by John Viega, Matt Messier and Pravir Chandra, ISBN 059600270X.

Using M2Crypto does not automatically make an SSL connection secure.
There are various steps that need to be made before we can make that
claim. Let's see how a simple client can establish a secure
connection::

    ctx = SSL.Context()
    ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, depth=9)
    if ctx.load_verify_locations('ca.pem') != 1: raise Exception('No CA certs')
    s = SSL.Connection(ctx)
    s.connect(server_address)
    # Normal protocol (for example HTTP) commands follow

The first line creates an SSL context. The defaults allow any SSL
version (except SSL version 2 which has known weaknesses) and sets the
allowed ciphers to secure ones.

The second line tells M2Crypto to perform certificate validation. The
flags shown above are typical for clients, and requires the server to
send a certificate. The depth parameter tells how long certificate
chains are allowed - 9 is pretty common default, although probably too
long in practice.

The third line loads the allowed root (certificate authority or CA)
certificates. Most Linux distributions come with CA certificates in
suitable format. You could also download the
`certdata.txt <http://mxr.mozilla.org/seamonkey/source//security/nss/lib/ckfw/builtins/certdata.txt?raw=1>`__
file from the
`NSS <http://www.mozilla.org/projects/security/pki/nss/>`__ project and
convert it with the little M2Crypto utility script
`demo/x509/certdata2pem.py <http://svn.osafoundation.org/m2crypto/trunk/demo/x509/certdata2pem.py>`__.

The fourth line creates an SSL connection object with the secure
context.

The fifth line connects to the server. During this time we perform the
last security step: just after connection, but before exchanging any
data, we compare the commonName (or subjectAltName DNS field) field in
the certificate the server returned to the server address we tried to
connect to. This happens automatically with SSL.Connection and the
Twisted wrapper class, and anything that uses those. In all other cases
you must do the check manually. It is recommended you call the
SSL.Checker to do the actual check.

SSL servers are different in that they typically do not require the
client to send a certificate, so there is usually no certificate
checking. Also, it is typically useless to perform host name checking.

Code Samples
============

The best samples of how to use the various SSL objects are in the tests
directory, and the test\_ssl.py file specifically. There are additional
samples in the demo directory, but they are not quaranteed to be up to
date.

NOTE: The tests and demos may not be secure as is. Use the information
above on how to make them secure.

ssldump
=======

ssldump "is an SSLv3/TLS network protocol analyser. It identifies TCP
connections on the chosen network interface and attempts to interpret
them as SSLv3/TLS traffic. When it identifies SSLv3/TLS traffic, it
decodes the records and displays them in a textual form to stdout. If
provided with the appropriate keying material, it will also decrypt the
connections and display the application data traffic.

If linked with OpenSSL, ssldump can display certificates in decoded form
and decrypt traffic (provided that it has the appropriate keying
material)."

ssldump is written by Eric Rescorla.
