#!/usr/bin/env python

"""Demonstrations of M2Crypto.httpslib.

Copyright (c) 1999-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: https_cli.py,v 1.4 2001/06/01 14:27:59 ngps Exp $'

import sys
from M2Crypto import Rand, SSL, httpslib


if sys.version[:3] == '1.5':

    def test_httpslib():
        ctx = SSL.Context('sslv3')
        #ctx.load_cert('client.pem')
        h = httpslib.HTTPS(ctx, '127.0.0.1:9443')
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


elif sys.version[:3] in ('2.0', '2.1'):

    def test_httpslib():
        ctx = SSL.Context('sslv3')
        #ctx.load_cert('client.pem')
        ctx.set_info_callback()
        h = httpslib.HTTPSConnection('127.0.0.1', 9443, ssl_context=ctx)
        h.set_debuglevel(1)
        h.putrequest('GET', '/')
        h.putheader('Accept', 'text/html')
        h.putheader('Accept', 'text/plain')
        h.putheader('Connection', 'close')
        h.endheaders()
        resp = h.getresponse()
        f = resp.fp
        c = 0
        while 1:
            # Either of following two works.
            #data = f.readline()   
            data = resp.read()
            if not data: break
            c = c + len(data)
            #print data
            sys.stdout.write(data)
            sys.stdout.flush()
        f.close()
        h.close()


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    test_httpslib()
    Rand.save_file('../randpool.dat')

