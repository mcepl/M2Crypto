#!/usr/bin/env python

"""
Unit tests for M2Crypto.EVP.

Copyright (c) 2004 Open Source Applications Foundation
Author: Heikki Toivonen
"""

RCS_id='$Id$'

import unittest
from M2Crypto import EVP, RSA

class EVPTestCase(unittest.TestCase):
    def _gen_callback(self, *args):
        pass
    
    def _assign_rsa(self):
        rsa = RSA.gen_key(512, 3, callback=self._gen_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa, capture=0) # capture=1 should cause crash
        return rsa
    
    def check_assign(self):
        rsa = self._assign_rsa()
        rsa.check_key()

def suite():
    return unittest.makeSuite(EVPTestCase, 'check')
    

if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

