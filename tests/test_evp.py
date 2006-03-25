#!/usr/bin/env python

"""
Unit tests for M2Crypto.EVP.

Copyright (c) 2004-2005 Open Source Applications Foundation
Author: Heikki Toivonen
"""

import unittest
from M2Crypto import EVP, RSA, util

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

    def check_as_der(self):
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa)
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
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha224')) == 2660082265842109788381286338540662430962855478412025487066970872635, util.octx_to_num(EVP.hmac('key', 'data', algo='sha224'))
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha256')) == 36273358097036101702192658888336808701031275731906771612800928188662823394256, util.octx_to_num(EVP.hmac('key', 'data', algo='sha256'))
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha384')) == 30471069101236165765942696708481556386452105164815350204559050657318908408184002707969468421951222432574647369766282, util.octx_to_num(EVP.hmac('key', 'data', algo='sha384'))
        assert util.octx_to_num(EVP.hmac('key', 'data', algo='sha512')) == 3160730054100700080556942280820129108466291087966635156623014063982211353635774277148932854680195471287740489442390820077884317620321797003323909388868696, util.octx_to_num(EVP.hmac('key', 'data', algo='sha512'))
        self.assertRaises(ValueError, EVP.hmac, 'key', 'data', algo='sha513')

def suite():
    return unittest.makeSuite(EVPTestCase, 'check')
    

if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

