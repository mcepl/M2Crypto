#!/usr/bin/env python

"""Unit tests for M2Crypto.RSA.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import unittest
import os, sha, tempfile
from M2Crypto import RSA, BIO, Rand, m2

class RSATestCase(unittest.TestCase):

    errkey = 'dsa.priv.pem'
    privkey = 'rsa.priv.pem'
    privkey2 = 'rsa.priv2.pem'
    pubkey = 'rsa.pub.pem'

    data = sha.sha('The magic words are squeamish ossifrage.').digest()

    e_padding_ok = ('pkcs1_padding', 'pkcs1_oaep_padding')

    s_padding_ok = ('pkcs1_padding',)
    s_padding_nok = ('no_padding', 'sslv23_padding', 'pkcs1_oaep_padding')

    def gen_callback(self, *args):
        pass

    def gen2_callback(self):
        pass

    def pp_callback(self, *args):
        # The passphrase for rsa.priv2.pem is 'qwerty'.
        return 'qwerty'

    def pp2_callback(self, *args):
        # Misbehaving passphrase callback.
        pass

    def check_loadkey_junk(self):
        self.assertRaises(RSA.RSAError, RSA.load_key, self.errkey)

    def check_loadkey_pp(self):
        rsa = RSA.load_key(self.privkey2, self.pp_callback)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def check_loadkey_pp_bad_cb(self):
        self.assertRaises(RSA.RSAError, RSA.load_key, self.privkey2, self.pp2_callback)

    def check_loadkey(self):
        rsa = RSA.load_key(self.privkey)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def check_loadkey_bio(self):
        keybio = BIO.MemoryBuffer(open(self.privkey).read()) 
        rsa = RSA.load_key_bio(keybio)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def check_keygen(self):
        rsa = RSA.gen_key(256, 65537, self.gen_callback)
        assert len(rsa) == 256
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def check_keygen_bad_cb(self):
        rsa = RSA.gen_key(256, 65537, self.gen2_callback)
        assert len(rsa) == 256
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def check_private_encrypt(self):
        priv = RSA.load_key(self.privkey)
        # pkcs1_padding
        for padding in self.s_padding_ok:
            p = getattr(RSA, padding)
            ctxt = priv.private_encrypt(self.data, p)
            ptxt = priv.public_decrypt(ctxt, p)
            assert ptxt == self.data
        # The other paddings.
        for padding in self.s_padding_nok:
            p = getattr(RSA, padding)
            self.assertRaises(RSA.RSAError, priv.private_encrypt, self.data, p)
        # Type-check the data to be encrypted.
        self.assertRaises(TypeError, priv.private_encrypt, self.gen_callback, RSA.pkcs1_padding)

    def check_public_encrypt(self):
        priv = RSA.load_key(self.privkey)
        # pkcs1_padding, pkcs1_oaep_padding
        for padding in self.e_padding_ok:
            p = getattr(RSA, padding)
            ctxt = priv.public_encrypt(self.data, p)
            ptxt = priv.private_decrypt(ctxt, p)
            assert ptxt == self.data
        # sslv23_padding
        ctxt = priv.public_encrypt(self.data, RSA.sslv23_padding)
        self.assertRaises(RSA.RSAError, priv.private_decrypt, ctxt, RSA.sslv23_padding)
        # no_padding
        self.assertRaises(RSA.RSAError, priv.public_encrypt, self.data, RSA.no_padding)
        # Type-check the data to be encrypted.
        self.assertRaises(TypeError, priv.public_encrypt, self.gen_callback, RSA.pkcs1_padding)
    
    def check_loadpub(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key()

    def check_loadpub_bad(self):
        self.assertRaises(RSA.RSAError, RSA.load_pub_key, self.errkey)

    def check_set_bn(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert m2.rsa_set_e(rsa.rsa, '\000\000\000\003\001\000\001') is None
        self.assertRaises(RSA.RSAError, m2.rsa_set_e, rsa.rsa, '\000\000\000\003\001')

    def check_newpub(self):
        old = RSA.load_pub_key(self.pubkey)
        new = RSA.new_pub_key(old.pub())
        assert new.check_key()
        assert len(new) == 512
        assert new.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        

def suite():
    return unittest.makeSuite(RSATestCase, 'check')
    

if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

