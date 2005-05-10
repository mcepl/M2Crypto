#!/usr/bin/env python

"""Unit tests for M2Crypto.X509.

Contributed by Toby Allsopp <toby@MI6.GEN.NZ> under M2Crypto's license.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2005 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

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
        ext1 = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
        ext2 = X509.new_extension('nsComment', 'Hello there')
        extstack = X509.X509_Extension_Stack()
        extstack.push(ext1)
        extstack.push(ext2)
        assert(extstack[1].get_name() == 'nsComment')
        x.add_extensions(extstack)
        x.sign(pk,'md5')
        return x, pk

    def check_mkreq(self):
        req, pk = self.mkreq(512, 0, 365)
        req.save_pem('tmp_request.pem')
        req2 = X509.load_request('tmp_request.pem')
        os.remove('tmp_request.pem')
        assert req.as_pem() == req2.as_pem()
        assert req.as_text() == req2.as_text()

    def check_mkcert(self):
        req, pk = self.mkreq(512, 0, 365)
        pkey = req.get_pubkey()
        assert(req.verify(pkey))
        sub = req.get_subject()
        cert = X509.X509()
        cert.set_serial_number(1)
        cert.set_version(2)
        cert.set_subject(sub)
        issuer = X509.X509_Name()
        issuer.CN = 'The Issuer Monkey'
        issuer.O = 'The Organization Otherwise Known as My CA, Inc.'
        cert.set_issuer(issuer)
        cert.set_pubkey(EVP.PKey(pkey))
        cert.set_pubkey(EVP.PKey(cert.get_pubkey()))
        ext = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
        ext.set_critical(0)
        cert.add_ext(ext)
        cert.sign(pk, 'sha1')
        assert(cert.get_ext('subjectAltName').get_name() == 'subjectAltName')
        assert(cert.get_ext_at(0).get_name() == 'subjectAltName')
        assert(cert.get_ext_at(0).get_value() == 'DNS:foobar.example.com')

def suite():
    return unittest.makeSuite(X509TestCase, 'check')


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

