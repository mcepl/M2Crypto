from __future__ import absolute_import

"""
M2Crypto is the most complete Python wrapper for OpenSSL
featuring RSA, DSA, DH, EC, HMACs, message digests, symmetric
ciphers (including AES); SSL functionality to implement clients
and servers; HTTPS extensions to Python's httplib, urllib, and
xmlrpclib; unforgeable HMAC'ing AuthCookies for web session
management; FTP/TLS client and server; and ZSmime: An S/MIME
messenger for Zope.  M2Crypto can also be used to provide SSL for
Twisted. Smartcards supported through the Engine interface.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.
"""
# noqa
from typing import Any

__version__: str = '0.43.0'
version: str = __version__

try:
    from distutils.version import StrictVersion as Version
except ImportError:
    try:
        from packaging.version import Version
    except ImportError:
        Version = None

if Version is not None:
    version_info: tuple = (0, 0, 0)
    __ver: Any = Version(__version__)
    if hasattr(__ver, u'_version'):
        version_info = tuple(__ver._version[1])
    elif hasattr(__ver, u'version'):
        version_info = __ver.version

from M2Crypto import m2

encrypt: int = 1
decrypt: int = 0
