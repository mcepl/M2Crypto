#!/usr/bin/env python

"""Demonstration of M2Crypto.xmlrpclib2.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: xmlrpc_cli.py,v 1.1 1999/10/19 15:23:19 ngps Exp $'

from M2Crypto.xmlrpclib2 import Server, SSL_Transport

# Server is Zope on ZServerSSL.
zs=Server('https://127.0.0.1:8443/QuickStart', SSL_Transport())
print zs.objectIds()

