#!/usr/bin/env python

"""Unit tests for M2Crypto.DSA.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id = '$Id$'

import unittest
import sha
from M2Crypto import DSA, BIO, Rand, m2

class DSATestCase(unittest.TestCase):

    errkey = 'rsa.priv.pem'
    privkey = 'dsa.priv.pem'
    param = 'dsa.param.pem'

    data = sha.sha('Can you spell subliminal channel?').digest()

    def callback(self, *args):
        pass

    def callback2(self):
        pass

    def check_loadkey_junk(self):
        self.assertRaises(ValueError, DSA.load_key, self.errkey)

    def check_loadkey(self):
        dsa = DSA.load_key(self.privkey)
        assert len(dsa) == 512

    def check_loadparam(self):
        # XXX more work needed
        dsa = DSA.load_params(self.param)
        assert len(dsa) == 512

    def check_sign(self):
        dsa = DSA.load_key(self.privkey)
        r, s = dsa.sign(self.data)
        assert dsa.verify(self.data, r, s)

    def check_sign_asn1(self):
        dsa = DSA.load_key(self.privkey)
        blob = dsa.sign_asn1(self.data)
        assert dsa.verify_asn1(self.data, blob)

    def check_sign_with_params_only(self):
        dsa = DSA.load_params(self.param)
        self.assertRaises(AssertionError, dsa.sign, self.data)
        self.assertRaises(AssertionError, dsa.sign_asn1, self.data)

    def check_verify(self):
        dsa = DSA.load_key(self.privkey)
        r, s = dsa.sign(self.data)
        dsa2 = DSA.load_params(self.param)
        self.assertRaises(AssertionError, dsa2.verify, self.data, r, s)

    def check_genparam(self):
        dsa = DSA.gen_params(256, self.callback)
        assert len(dsa) == 512

    def check_genparam_bad_cb(self):
        dsa = DSA.gen_params(256, self.callback2)
        assert len(dsa) == 512


def suite():
    return unittest.makeSuite(DSATestCase, 'check')
    

if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

