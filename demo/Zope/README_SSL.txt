
--------------
 18 Mar 2001
--------------

Whew! It's been more than a year! ZServerSSL was last released on 1 Feb
2000 for Zope 2.1.3.

It has now been dusted off and re-released for Zope 2.3.0.

Tested with Zope-2.3.0-win32-x86 with M2Crypto for Python1.

Tested with Zope-2.3.0-src on FreeBSD with M2Crypto for 
both Python1 and Python2.

Interoperated with Netscape, IE and Opera on Win32, and also Netscape
on FreeBSD.

X.509 certificate-based client authentication for HTTPS and the
encrypting monitor, both features of the ZServerSSL released a year
ago, to come RSN!


Following are the installation intructions for ZServerSSL:

Let <m2_top_dir> be the top-level directory of the M2Crypto
distribution, i.e., <m2_top_dir> should contain the files LICENSE,
README, etc. and the directories M2Crypto, demo, swig, tests, etc.

The ZServerSSL distribution is found in <m2_top_dir>/demo/Zope
and contains the following files:

README_M2Crypto.txt             - Overall README file.
README_SSL.txt                  - This file.
README_certs.txt                - README for installing your own certificates.
ca.pem                          - M2Crypto's demo CA cert. 
server.pem                      - Demo server cert and key pair.
dh1024.pem                      - EDH parameters used by the SSL protocol.
randpool.dat                    - Cryptographic "randomness" seed.
z2s.py                          - Replacement Zope start-up program.
ZServer/__init__.py             - A replacement.
ZServer/HTTPS_Server.py         - ZServer's HTTPS server. 
ZServer/medusa/https_server.py  - The underlying HTTPS plumbing.

The file ca.pem contains a demo CA certificate. The file server.pem
contains a certificate for the server, signed by the CA; its RSA private
key is included in the same file and is not protected by a passphrase.
These files are in PEM format. Plug in your certificates and key files if
you wish; see README_certs.txt for instructions.

Copy these files into their corresponding locations in the Zope directory
tree; e.g., z2s.py, randpool.dat and *.pem should go into the Zope top-
level directory.

Build and install M2Crypto: this means the directory <m2_top_dir>/M2Crypto 
should be on the PYTHONPATH. 

Start Zope thusly:

    python -D -X -w 9080 -x 9443

This starts a HTTP server on port 9080 and an HTTPS server on port 9443.

Connect with a browser. Also, if you have installed the eff-bot's
xmlrpclib, try <m2_top_dir>/demo/ssl/xmlrpc_cli.py.

Have fun! 

Usual disclaimers apply. Feedback is very much appreciated.

-- 
Ng Pheng Siong <ngps@post1.com> * http://www.post1.com/home/ngps

$Id: README_SSL.txt,v 1.1 2001/03/18 15:46:34 ngps Exp $
