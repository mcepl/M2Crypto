#!/usr/bin/env python

"""Demonstrations of M2Crypto.httpslib.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: https_cli.py,v 1.3 2000/11/29 15:16:51 ngps Exp $'

import sys
from M2Crypto import Rand, SSL, httpslib


def test_httpslib_15():
    ctx = SSL.Context('sslv3')
    #ctx.load_cert('client.pem')
    h = httpslib.HTTPS(ctx, '127.0.0.1:443')
    h.putrequest('GET', '/')
    h.putheader('Accept', 'text/html')
    h.putheader('Accept', 'text/plain')
    h.endheaders()
    errcode, errmsg, headers = h.getreply()
    f = h.getfile()
    while 1:
        data = f.read()   
        if not data:
            break
        sys.stdout.write(data)
    f.close()


def test_httpslib_20():
    ctx = SSL.Context('sslv3')
    #ctx.load_cert('client.pem')
    h = httpslib.HTTPSConnection('127.0.0.1', 443, ssl_context=ctx)
    h.set_debuglevel(1)
    h.putrequest('GET', '/')
    h.putheader('Accept', 'text/html')
    h.putheader('Accept', 'text/plain')
    h.putheader('Connection', 'close')
    h.endheaders()
    resp = h.getresponse()
    f = resp.fp
    while 1:
        # Either of following two works.
        #data = f.readline()   
        data = resp.read()
        if not data: break
        print data
    f.close()
    h.close()

if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    if sys.version[:3] == '2.0':
        test_httpslib_20()
    elif sys.version[:3] == '1.5':
        test_httpslib_15()
    Rand.save_file('../randpool.dat')

