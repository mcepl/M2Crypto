#!/usr/bin/env python

"""Demonstrations of M2Crypto.urllib2 and M2Crypto.httpslib.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: https_cli.py,v 1.2 2000/04/17 15:58:37 ngps Exp $'

import sys
from M2Crypto import SSL, httpslib, urllib2

def test_httpslib_m():
    # Real cheezy multi-threading. ;-)
    # The following simply interleaves three copies of test_httpslib,
    # and has each asking for a different resource.

    # Change the following to suit your system.
    host = '127.0.0.1:9443'
    req1 = '/apache/'
    req2 = '/cyrus/'
    req3 = '/index.html'

    ctx=SSL.Context('sslv3')
    ctx.load_cert('client.pem')

    h1=httpslib.HTTPS(ctx, host)
    h1.putrequest('GET', req1)
    h1.putheader('Accept', 'text/html')

    h2=httpslib.HTTPS(ctx, host)

    h1.putheader('Accept', 'text/plain')

    h3=httpslib.HTTPS(ctx, host)
    h3.putrequest('GET', req2)
    h3.putheader('Accept', 'text/html')
    h3.putheader('Accept', 'text/plain')

    h2.putrequest('GET', req3)
    h2.putheader('Accept', 'text/html')

    h1.endheaders()

    h2.putheader('Accept', 'text/plain')
    h2.endheaders()
    errcode, errmsg, headers=h2.getreply()
    f2=h2.getfile()
    while 1:
        data=f2.readline()   
        if not data:
            break
        sys.stdout.write(data)
    f2.close()

    h3.endheaders()
    errcode, errmsg, headers=h3.getreply()
    f3=h3.getfile()

    errcode, errmsg, headers=h1.getreply()
    f1=h1.getfile()

    while 1:
        data=f3.readline()   
        if not data:
            break
        sys.stdout.write(data)
    f3.close()

    while 1:
        data=f1.readline()   
        if not data:
            break
        sys.stdout.write(data)
    f1.close()

def test_httpslib():
    ctx=SSL.Context('sslv3')
    ctx.load_cert('client.pem')
    h=httpslib.HTTPS(ctx, '127.0.0.1:9443')
    h.putrequest('GET', '/')
    h.putheader('Accept', 'text/html')
    h.putheader('Accept', 'text/plain')
    h.endheaders()
    errcode, errmsg, headers=h.getreply()
    f=h.getfile()
    while 1:
        data=f.readline()   
        if not data:
            break
        sys.stdout.write(data)
    f.close()

def test_urllib2():
    url=urllib2.urlopen('https://127.0.0.1:9443/')
    data=url.readlines()
    for d in data:
        sys.stdout.write(d)
    url.close()

if __name__=='__main__':
    test_urllib2()
    test_httpslib_m()
    test_httpslib()
    test_httpslib_m()

