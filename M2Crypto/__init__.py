"""
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to
Python's httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies
for web session management; FTP/TLS client and server; S/MIME; ZServerSSL:
A HTTPS server for Zope and ZSmime: An S/MIME messenger for Zope.
M2Crypto can also be used to provide SSL for Twisted. Smartcards supported
through the Engine interface.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.
"""

version_info = (0, 22)
version = '.'.join([str(_v) for _v in version_info])

import __m2crypto
from . import m2
from . import ASN1
from . import AuthCookie
from . import BIO
from . import BN
from . import Rand
from . import DH
from . import DSA
if m2.OPENSSL_VERSION_NUMBER >= 0x90800F and m2.OPENSSL_NO_EC == 0:
    from . import EC
from . import Err
from . import Engine
from . import EVP
from . import RSA
from . import RC4
from . import SMIME
from . import SSL
from . import X509
from . import PGP
from . import m2urllib
# Backwards compatibility.
urllib2 = m2urllib

import sys
if sys.version_info >= (2,4):
    from . import m2urllib2
del sys

from . import ftpslib
from . import httpslib
from . import m2xmlrpclib
from . import threading
from . import util

encrypt=1
decrypt=0

__m2crypto.lib_init()
