#!/usr/bin/env python

"""Unit tests for non-networking functionality of M2Crypto.SSL.

Copyright (c) 2000-2002 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import unittest
from M2Crypto import Rand
from M2Crypto.SSL import *

class SSLSupportTestCase(unittest.TestCase):

    def setUp(self):
        self.ctx = Context()

    def tearDown(self):
        pass

    def test_load_cert_nok1(self):
        self.failUnlessRaises(SSLError, self.ctx.load_cert, 'server_key.pem')


def suite():
    return unittest.makeSuite(SSLSupportTestCase)
    

if __name__ == '__main__':
    Rand.load_file('../randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('../randpool.dat')

