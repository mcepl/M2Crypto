#!/usr/bin/env python

from M2Crypto import Rand, SSL, httpslib

def get_https():
    ctx = SSL.Context()
    h = httpslib.HTTPSConnection('127.0.0.1', 9443, ssl_context=ctx)
    h.set_debuglevel(1)
    h.putrequest('GET', '/')
    h.endheaders()
    resp = h.getresponse()
    while 1:
        data = resp.read()
        if not data: 
            break
        print data
    h.close()

Rand.load_file('../randpool.dat', -1) 
get_https()
Rand.save_file('../randpool.dat')

