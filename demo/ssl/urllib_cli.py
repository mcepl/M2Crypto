#!/usr/bin/env python

"""Demonstrations of M2Crypto.m2urllib2.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: urllib_cli.py,v 1.1 2000/11/29 15:18:22 ngps Exp $'

import sys
from M2Crypto import Rand, SSL, m2urllib


def test_urllib():
    url = m2urllib.urlopen('https://127.0.0.1:443/')
    while 1:
        data = url.read()
        if not data:
            break
        sys.stdout.write(data)
    url.close()


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    test_urllib()
    Rand.save_file('../randpool.dat')

