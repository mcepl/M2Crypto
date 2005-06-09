#!/usr/bin/env python

"""Unit tests for M2Crypto.DH.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import unittest
from M2Crypto import DH, BIO, Rand, m2
import sys

class DHTestCase(unittest.TestCase):

    params = 'dhparam.pem'

    def genparam_callback(self, *args):
        pass 

    def genparam_callback2(self):
        pass 

    def check_init_junk(self):
        self.assertRaises(TypeError, DH.DH, 'junk')

    def check_gen_params(self):
        a = DH.gen_params(128, 2, self.genparam_callback)
        assert a.check_params() == 0

    def check_gen_params_bad_cb(self):
        a = DH.gen_params(128, 2, self.genparam_callback2)
        assert a.check_params() == 0

    def check_print_params(self):
        a = DH.gen_params(128, 2, self.genparam_callback)
        bio = BIO.MemoryBuffer()
        a.print_params(bio)
        params = bio.read()
        if sys.version[:3] in ('2.0', '2.1'):
            assert params.find('(128 bit)')
            assert params.find('generator: 2 (0x2)')
        elif sys.version[:3] == '1.5': 
            import string
            assert string.find(params, '(128 bit)')
            assert string.find(params, 'generator: 2 (0x2)')

    def check_load_params(self):
        a = DH.load_params('dhparams.pem')
        assert a.check_params() == 0

    def check_compute_key(self):
        a = DH.load_params('dhparams.pem')
        b = DH.set_params(a.p, a.g)
        a.gen_key()
        b.gen_key()
        ak = a.compute_key(b.pub)
        bk = b.compute_key(a.pub)
        assert ak == bk


def suite():
    return unittest.makeSuite(DHTestCase, 'check_')


if __name__=='__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

