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
__version__ = '0.42.0'
version = __version__  # type: str

try:
    from distutils.version import StrictVersion as Version
except ImportError:
    try:
        from packaging.version import Version
    except ImportError:
        Version = None

if Version is not None:
    __ver = Version(__version__)
    if hasattr(__ver, '_version'):
        version_info = tuple(__ver._version[1])
    elif hasattr(__ver, 'version'):
        version_info = __ver.version

from M2Crypto import m2

encrypt = 1
decrypt = 0

m2.lib_init()
