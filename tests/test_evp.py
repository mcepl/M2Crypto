#!/usr/bin/env python

"""
Unit tests for M2Crypto.EVP.

Copyright (c) 2004-2005 Open Source Applications Foundation
Author: Heikki Toivonen
"""

import unittest
import cStringIO, sha
from M2Crypto import EVP, RSA, util, Rand

class EVPTestCase(unittest.TestCase):
    def _gen_callback(self, *args):
        pass
    
    def _pass_callback(self, *args):
        return 'foobar'
    
    def _assign_rsa(self):
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa, capture=0) # capture=1 should cause crash
        return rsa
    
    def check_assign(self):
        rsa = self._assign_rsa()
        rsa.check_key()
        
    def check_pem(self):
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa)
        assert pkey.as_pem(callback=self._pass_callback) != pkey.as_pem(cipher=None)
        self.assertRaises(ValueError, pkey.as_pem, cipher='noXX$$%%suchcipher',
                          callback=self._pass_callback)
                          
    def check_as_der(self):
        """
        Test DER encoding the PKey instance after assigning 
        a RSA key to it.
        """
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa)
        der_blob = pkey.as_der()        
        #A quick but not thorough sanity check
        assert len(der_blob) == 92
          
        
    def check_MessageDigest(self):
        self.assertRaises(ValueError, EVP.MessageDigest, 'sha513')
        md = EVP.MessageDigest('sha1')
        assert md.update('Hello') == 1
        assert util.octx_to_num(md.final()) == 1415821221623963719413415453263690387336440359920

    def check_as_der_capture_key(self):
        """
        Test DER encoding the PKey instance after assigning 
        a RSA key to it. Have the PKey instance capture the RSA key.
        """
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa, 1)
        der_blob = pkey.as_der()
        #A quick but not thorough sanity check
        assert len(der_blob) == 92

    def check_size(self):
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa)
        size = pkey.size() 
        assert size == 64
        
    def check_hmac(self):
        assert util.octx_to_num(EVP.hmac('key', 'data')) == 92800611269186718152770431077867383126636491933, util.octx_to_num(EVP.hmac('key', 'data'))
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='md5')) == 209168838103121722341657216703105225176, util.octx_to_num(EVP.hmac('key', 'data', algo='md5'))
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='ripemd160')) == 1176807136224664126629105846386432860355826868536, util.octx_to_num(EVP.hmac('key', 'data', algo='ripemd160'))
        
        if m2.OPENSSL_VERSION_NUMBER >= 0x90800F:
            assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha224')) == 2660082265842109788381286338540662430962855478412025487066970872635, util.octx_to_num(EVP.hmac('key', 'data', algo='sha224'))
            assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha256')) == 36273358097036101702192658888336808701031275731906771612800928188662823394256, util.octx_to_num(EVP.hmac('key', 'data', algo='sha256'))
            assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha384')) == 30471069101236165765942696708481556386452105164815350204559050657318908408184002707969468421951222432574647369766282, util.octx_to_num(EVP.hmac('key', 'data', algo='sha384'))
            assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha512')) == 3160730054100700080556942280820129108466291087966635156623014063982211353635774277148932854680195471287740489442390820077884317620321797003323909388868696, util.octx_to_num(EVP.hmac('key', 'data', algo='sha512'))
        
        self.assertRaises(ValueError, EVP.hmac, 'key', 'data', algo='sha513')


    def check_get_rsa(self):
        """
        Testing retrieving the RSA key from the PKey instance.
        """
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa) 
        rsa2 = pkey.get_rsa()
        assert rsa.e == rsa2.e
        assert rsa.n == rsa2.n
        # Not sure why these two are not the same...
        assert rsa.as_pem(callback=self._pass_callback)
        assert rsa2.as_pem(callback=self._pass_callback)
        
        message = "This is the message string"
        digest = sha.sha(message).digest()
        assert rsa.sign(digest) == rsa2.sign(digest)
        
        rsa3 = RSA.gen_key(512, 3, callback=self._gen_callback)
        assert rsa.sign(digest) != rsa3.sign(digest)
    
    def check_get_rsa_fail(self):
        """
        Testing trying to retrieve the RSA key from the PKey instance
        when it is not holding a RSA Key. Should raise a ValueError.
        """
        pkey = EVP.PKey()
        self.assertRaises(ValueError, pkey.get_rsa)


class CipherTestCase(unittest.TestCase):
    def cipher_filter(self, cipher, inf, outf):
        while 1:
            buf=inf.read()
            if not buf:
                break
            outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue()

    def try_algo(self, algo):
        enc = 1
        dec = 0
        otxt='against stupidity the gods themselves contend in vain'
    
        k=EVP.Cipher(algo, 'goethe','12345678', enc, 1, 'sha1', 'saltsalt', 5)
        pbuf=cStringIO.StringIO(otxt)
        cbuf=cStringIO.StringIO()
        ctxt=self.cipher_filter(k, pbuf, cbuf)
        pbuf.close()
        cbuf.close()
    
        j=EVP.Cipher(algo, 'goethe','12345678', dec, 1, 'sha1', 'saltsalt', 5)
        pbuf=cStringIO.StringIO()
        cbuf=cStringIO.StringIO(ctxt)
        ptxt=self.cipher_filter(j, cbuf, pbuf)
        pbuf.close()
        cbuf.close()
    
        assert otxt == ptxt, '%s algorithm cipher test failed' % algo
        
    def check_ciphers(self):
        ciphers=['bf_ecb', 'bf_cbc', 'bf_cfb', 'bf_ofb',\
            #'idea_ecb', 'idea_cbc', 'idea_cfb', 'idea_ofb',\
            'cast5_ecb', 'cast5_cbc', 'cast5_cfb', 'cast5_ofb',\
            #'rc5_ecb', 'rc5_cbc', 'rc5_cfb', 'rc5_ofb',\
            'des_ecb', 'des_cbc', 'des_cfb', 'des_ofb',\
            'des_ede_ecb', 'des_ede_cbc', 'des_ede_cfb', 'des_ede_ofb',\
            'des_ede3_ecb', 'des_ede3_cbc', 'des_ede3_cfb', 'des_ede3_ofb',\
            'aes_128_ecb', 'aes_128_cbc', 'aes_128_cfb', 'aes_128_ofb',\
            'aes_192_ecb', 'aes_192_cbc', 'aes_192_cfb', 'aes_192_ofb',\
            'aes_256_ecb', 'aes_256_cbc', 'aes_256_cfb', 'aes_256_ofb',\
            'rc4', 'rc2_40_cbc']
        for i in ciphers:
            self.try_algo(i)

        self.assertRaises(ValueError, self.try_algo, 'nosuchalgo4567')

def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(EVPTestCase, 'check'))
    suite.addTest(unittest.makeSuite(CipherTestCase, 'check'))
    return suite    

if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

