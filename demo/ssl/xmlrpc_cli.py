#!/usr/bin/env python

"""Demonstration of M2Crypto.xmlrpclib2.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: xmlrpc_cli.py,v 1.2 2000/02/03 16:37:50 ngps Exp $'

from M2Crypto.xmlrpclib2 import Server, SSL_Transport

# XXX This works for Zope 2.0.x but not for Zope 2.1.x.
# Server is Zope on ZServerSSL.
#zs=Server('https://127.0.0.1:8443/QuickStart', SSL_Transport())
#print zs.objectIds()

# Server is ../https/START.py.
zs=Server('https://127.0.0.1:9443/RPC2', SSL_Transport())
print zs.Testing(1, 2, 3)
print zs.BringOn('SOAP')


