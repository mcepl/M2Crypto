#!/usr/bin/env python

"""Demonstrations of M2Crypto.m2urllib2.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

from M2Crypto import Rand, SSL, m2urllib

def test_urllib():
    url = m2urllib.FancyURLopener()
    url.addheader('Connection', 'close')
    u = url.open('https://127.0.0.1:9443/')
    while 1:
        data = u.read()
        if not data: break
        print data
    u.close()


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    test_urllib()
    Rand.save_file('../randpool.dat')

