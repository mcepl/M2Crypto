#!/usr/bin/env python

"""Unit tests for M2Crypto.ASN1.

Copyright (c) 2005 Open Source Applications Foundation. All rights reserved."""

import unittest, time, datetime, logging
logging.basicConfig(level=logging.DEBUG)
from M2Crypto import ASN1, __m2crypto as m2

class ASN1TestCase(unittest.TestCase):

    def test_Integer(self):
        asn1ptr = m2.asn1_integer_new()
        m2.asn1_integer_set(asn1ptr, 1)
        a = ASN1.ASN1_Integer(asn1ptr, 1)
        self.assertEqual(a.int, 1)

        # FIXME This leads to crash.
        # #0  0x00007f58c2d61036 in BN_bin2bn (s=0x2985000 <Address 0x2985000 out of bounds>,
        #     len=<optimized out>, ret=0x270e190, ret@entry=0x0) at bn_lib.c:607
        # #1  0x00007f58c2da7b26 in ASN1_INTEGER_to_BN (ai=0x270e190, bn=bn@entry=0x0) at a_int.c:450
        # #2  0x00007f58c332bf7d in asn1_integer_get (asn1=<optimized out>)
        #     at SWIG/_m2crypto_wrap.c:6858
        # #3  0x00007f58c332c07a in _wrap_asn1_integer_get (self=<optimized out>, args=<optimized out>)
        #     at SWIG/_m2crypto_wrap.c:23415

        # m2.asn1_integer_set(asn1ptr, 42)
        # a = ASN1.ASN1_Integer(asn1ptr, 1)
        # logging.debug("a = %s", repr(a))
        # self.assertEqual(a.int, 42)

    def test_BitSTring(self):
        pass # XXX Dunno how to test

    def test_String(self):
        asn1ptr = m2.asn1_string_new()
        # FIXME this is probably wrong ... asn1_string_set should have
        # Python string as its parameter.
        text = b'hello there'
        # In RFC2253 format:
        # #040B68656C6C6F207468657265
        #      h e l l o   t h e r e
        m2.asn1_string_set(asn1ptr, text)
        a = ASN1.ASN1_String(asn1ptr, 1)
        self.assertEqual(a.as_text(), 'hello there')
        self.assertEqual(a.as_text(flags=m2.ASN1_STRFLGS_RFC2253), '#040B68656C6C6F207468657265')
        self.assertEqual(a.as_text(), str(a))

    def test_Object(self):
        pass # XXX Dunno how to test

    def test_UTCTIME(self):
        asn1 = ASN1.ASN1_UTCTIME()
        assert str(asn1) == 'Bad time value'

        format = '%b %d %H:%M:%S %Y GMT'
        utcformat = '%y%m%d%H%M%SZ'

        s = '990807053011Z'
        asn1.set_string(s)
        #assert str(asn1) == 'Aug  7 05:30:11 1999 GMT'
        t1 = time.strptime(str(asn1), format)
        t2 = time.strptime(s, utcformat)
        self.assertEqual(t1, t2)

        asn1.set_time(500)
        #assert str(asn1) == 'Jan  1 00:08:20 1970 GMT'
        t1 = time.strftime(format, time.strptime(str(asn1), format))
        t2 = time.strftime(format, time.gmtime(500))
        self.assertEqual(t1, t2)

        t = int(time.time()) + time.timezone
        asn1.set_time(t)
        t1 = time.strftime(format, time.strptime(str(asn1), format))
        t2 = time.strftime(format, time.gmtime(t))
        self.assertEqual(t1, t2)

    def test_UTCTIME_datetime(self):
        asn1 = ASN1.ASN1_UTCTIME()
        # Test get_datetime and set_datetime
        t = time.time()
        dt = datetime.datetime.fromtimestamp(int(t))
        udt = dt.replace(tzinfo=ASN1.LocalTimezone()).astimezone(ASN1.UTC)
        asn1.set_time(int(t))
        t1 = str(asn1)
        asn1.set_datetime(dt)
        t2 = str(asn1)
        self.assertEqual(t1, t2)
        self.assertEqual(str(udt), str(asn1.get_datetime()))

        dt = dt.replace(tzinfo=ASN1.LocalTimezone())
        asn1.set_datetime(dt)
        t2 = str(asn1)
        self.assertEqual(t1, t2)
        self.assertEqual(str(udt), str(asn1.get_datetime()))

        dt = dt.astimezone(ASN1.UTC)
        asn1.set_datetime(dt)
        t2 = str(asn1)
        self.assertEqual(t1, t2)
        self.assertEqual(str(udt), str(asn1.get_datetime()))


def suite():
    return unittest.makeSuite(ASN1TestCase)


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
