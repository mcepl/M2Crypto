#!/usr/bin/env python

"""Unit tests for M2Crypto.RSA.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

import unittest
import sha, md5, os
from M2Crypto import RSA, BIO, Rand, m2, EVP, X509

class RSATestCase(unittest.TestCase):

    errkey = 'tests/dsa.priv.pem'
    privkey = 'tests/rsa.priv.pem'
    privkey2 = 'tests/rsa.priv2.pem'
    pubkey = 'tests/rsa.pub.pem'

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

    def test_loadkey_junk(self):
        self.assertRaises(RSA.RSAError, RSA.load_key, self.errkey)

    def test_loadkey_pp(self):
        rsa = RSA.load_key(self.privkey2, self.pp_callback)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def test_loadkey_pp_bad_cb(self):
        self.assertRaises(RSA.RSAError, RSA.load_key, self.privkey2, self.pp2_callback)

    def test_loadkey(self):
        rsa = RSA.load_key(self.privkey)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        self.assertEqual(rsa.n, '\x00\x00\x00A\x00\xd4\rc\xb4C\xf4\x16\xaba\x1b&1\xac\xcc\xd6\x17{k\xeb\xb7A\xe3\x0f\x15\x94;!\xcf\x81\x9ag\x96\x1e\xfb\xd5?\x86#\xca\xedm\xea\xf0.\xb7\xb9\x8a\x91\xa0\xde)\xb4\xf7\xca!\x95R\x00\x04Q\xa5\x8c^\xa1')
        self.assertRaises(AttributeError, getattr, rsa, 'nosuchprop')
        assert rsa.check_key() == 1

    def test_loadkey_bio(self):
        keybio = BIO.MemoryBuffer(open(self.privkey).read()) 
        rsa = RSA.load_key_bio(keybio)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def test_keygen(self):
        rsa = RSA.gen_key(512, 65537, self.gen_callback)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def test_keygen_bad_cb(self):
        rsa = RSA.gen_key(512, 65537, self.gen2_callback)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        assert rsa.check_key() == 1

    def test_private_encrypt(self):
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

    def test_public_encrypt(self):
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

    def test_x509_public_encrypt(self):
        x509 = X509.load_cert("tests/recipient.pem")
        rsa = x509.get_pubkey().get_rsa()
        rsa.public_encrypt("data", RSA.pkcs1_padding)
        
    def test_loadpub(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert len(rsa) == 512
        assert rsa.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        self.assertRaises(RSA.RSAError, setattr, rsa, 'e', '\000\000\000\003\001\000\001')
        self.assertRaises(RSA.RSAError, rsa.private_encrypt, 1)
        self.assertRaises(RSA.RSAError, rsa.private_decrypt, 1)
        assert rsa.check_key()

    def test_loadpub_bad(self):
        self.assertRaises(RSA.RSAError, RSA.load_pub_key, self.errkey)

    def test_savepub(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert rsa.as_pem() # calls save_key_bio
        f = 'tests/rsa_test.pub'
        try:
            self.assertEquals(rsa.save_key(f), 1)
        finally:
            try:
                os.remove(f)
            except IOError:
                pass

    def test_set_bn(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert m2.rsa_set_e(rsa.rsa, '\000\000\000\003\001\000\001') is None
        self.assertRaises(RSA.RSAError, m2.rsa_set_e, rsa.rsa, '\000\000\000\003\001')

    def test_newpub(self):
        old = RSA.load_pub_key(self.pubkey)
        new = RSA.new_pub_key(old.pub())
        assert new.check_key()
        assert len(new) == 512
        assert new.e == '\000\000\000\003\001\000\001' # aka 65537 aka 0xf4
        
    def test_sign_and_verify(self):
        """
        Testing signing and verifying digests
        """
        algos = {'sha1':'', 
                 'ripemd160':'',
                 'md5':''}

        if m2.OPENSSL_VERSION_NUMBER >= 0x90800F:
            algos['sha224'] = ''
            algos['sha256'] = ''
            algos['sha384'] = '' 
            algos['sha512'] = '' 

        message = "This is the message string"
        digest = sha.sha(message).digest()
        rsa = RSA.load_key(self.privkey)
        rsa2 = RSA.load_pub_key(self.pubkey)
        for algo in algos.keys():
            signature = rsa.sign(digest, algo)
            #assert signature == algos[algo], 'mismatched signature with algorithm %s: signature=%s' % (algo, signature)
            verify = rsa2.verify(digest, signature, algo) 
            assert verify == 1, 'verification failed with algorithm %s' % algo
    
    def test_sign_and_verify_rsassa_pss(self):
        """
        Testing signing and verifying using rsassa_pss

        The maximum size of the salt has to decrease as the
        size of the digest increases because of the size of 
        our test key limits it.
        """
        algos = {'sha1':43, 
                 'ripemd160':43,
                 'md5':47}

        if m2.OPENSSL_VERSION_NUMBER >= 0x90800F:
            algos['sha224'] = 35
            algos['sha256'] = 31
            algos['sha384'] = 15
            algos['sha512'] = 0 
    
        message = "This is the message string"
        digest = sha.sha(message).digest()
        rsa = RSA.load_key(self.privkey)
        rsa2 = RSA.load_pub_key(self.pubkey)
        for algo, salt_max in algos.iteritems():
            for salt_length in range(0, salt_max):
                signature = rsa.sign_rsassa_pss(digest, algo, salt_length)
                verify = rsa2.verify_rsassa_pss(digest, signature, algo, salt_length) 
                assert verify == 1, 'verification failed with algorithm %s salt length %d' % (algo, salt_length)

    def test_sign_bad_method(self):
        """
        Testing calling sign with an unsupported message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        message = "This is the message string"
        digest = md5.md5(message).digest() 
        self.assertRaises(ValueError, rsa.sign, 
                          digest, 'bad_digest_method') 
    
    def test_verify_bad_method(self):
        """
        Testing calling verify with an unsupported message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        message = "This is the message string"
        digest = md5.md5(message).digest() 
        signature = rsa.sign(digest, 'sha1')
        self.assertRaises(ValueError, rsa.verify,
                          digest, signature, 'bad_digest_method') 

    def test_verify_mismatched_algo(self):
        """
        Testing verify to make sure it fails when we use a different
        message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        message = "This is the message string"
        digest = sha.sha(message).digest() 
        signature = rsa.sign(digest, 'sha1')
        rsa2 = RSA.load_pub_key(self.pubkey)
        self.assertRaises(RSA.RSAError, rsa.verify, 
                          digest, signature, 'md5')
    
    def test_sign_fail(self):
        """
        Testing sign to make sure it fails when I give it
        a bogus digest. Looking at the RSA sign method
        I discovered that with the digest methods we use
        it has to be longer than a certain length.
        """
        rsa = RSA.load_key(self.privkey)
        digest = """This string should be long enough to warrant an error in
        RSA_sign"""
         
        self.assertRaises(RSA.RSAError, rsa.sign, digest)
    
    def test_verify_bad_signature(self):
        """
        Testing verify to make sure it fails when we use a bad signature
        """
        rsa = RSA.load_key(self.privkey)
        message = "This is the message string"
        digest = sha.sha(message).digest() 

        otherMessage = "Abracadabra"
        otherDigest = sha.sha(otherMessage).digest() 
        otherSignature = rsa.sign(otherDigest)

        self.assertRaises(RSA.RSAError, rsa.verify, 
                          digest, otherSignature)
    
        
def suite():
    return unittest.makeSuite(RSATestCase)
    

if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

