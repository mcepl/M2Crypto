#!/usr/bin/env python

"""Unit tests for M2Crypto.X509.

Contributed by Toby Allsopp <toby@MI6.GEN.NZ> under M2Crypto's license."""

RCS_id='$Id: test_x509.py,v 1.1 2003/05/11 16:17:25 ngps Exp $'

import unittest
import os
from M2Crypto import X509, EVP, RSA, Rand

class X509TestCase(unittest.TestCase):

    def callback(self, *args):
        pass

    def mkreq(self, bits, serial, days):
        pk=EVP.PKey()
        x=X509.Request()
        rsa=RSA.gen_key(bits,65537,self.callback)
        pk.assign_rsa(rsa)
        rsa=None # should not be freed here
        x.set_pubkey(pk)
        name=x.get_subject()
        name.C = "UK"
        name.CN = "OpenSSL Group"
        x.sign(pk,'md5')
        return x, pk

    def check_mkreq(self):
        req, pk = self.mkreq(512, 0, 365)
        req.save_pem('tmp_request.pem')
        req2 = X509.load_request('tmp_request.pem')
        os.remove('tmp_request.pem')
        assert req.as_pem() == req2.as_pem()
        assert req.as_text() == req2.as_text()

def suite():
    return unittest.makeSuite(X509TestCase, 'check')


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

