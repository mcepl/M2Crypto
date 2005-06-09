#!/usr/bin/env python

"""Demonstrations of M2Crypto.httpslib.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import sys
from M2Crypto import Rand, SSL, httpslib, threading


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


elif sys.version[0] == '2':

    def test_httpslib():
        ctx = SSL.Context('sslv2')
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
    #threading.init()
    test_httpslib()
    #threading.cleanup()
    Rand.save_file('../randpool.dat')

