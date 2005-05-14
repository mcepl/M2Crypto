#!/usr/bin/env python

"""Unit tests for M2Crypto.ASN1.

Copyright (c) 2005 Open Source Applications Foundation. All rights reserved."""

RCS_id='$Id$'

import unittest, time
from M2Crypto import ASN1

class ASN1TestCase(unittest.TestCase):

    def check_Integer(self):
        pass # XXX Dunno how to test

    def check_BitSTring(self):
        pass # XXX Dunno how to test

    def check_String(self):
        pass # XXX Dunno how to test

    def check_Object(self):
        pass # XXX Dunno how to test

    def check_UTCTIME(self):
        asn1 = ASN1.ASN1_UTCTIME()
        assert str(asn1) == 'Bad time value'
        
        asn1.set_string('990807053011Z')
        assert str(asn1) == 'Aug  7 05:30:11 1999 GMT'
        
        asn1.set_time(500)
        assert str(asn1) == 'Jan  1 00:08:20 1970 GMT'
        
        t = long(time.time()) + time.timezone
        asn1.set_time(t)
        t2 = time.strftime('%b %d %H:%M:%S %Y', time.gmtime(t))
        assert str(asn1)[:-4] == str(t2)
         

def suite():
    return unittest.makeSuite(ASN1TestCase, 'check')


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

