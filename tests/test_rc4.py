#!/usr/bin/env python
from __future__ import absolute_import

"""Unit tests for M2Crypto.RC4.

Copyright (c) 2009 Heikki Toivonen. All rights reserved."""

try:
    import unittest2 as unittest
except ImportError:
    import unittest
from M2Crypto import RC4, Rand
from binascii import hexlify

from tests.fips import fips_mode

class RC4TestCase(unittest.TestCase):

    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_vectors(self):
        """
        Test with test vectors from Wikipedia: http://en.wikipedia.org/wiki/Rc4
        """
        vectors = (('Key', 'Plaintext', 'BBF316E8D940AF0AD3'),
                   ('Wiki', 'pedia', '1021BF0420'),
                   ('Secret', 'Attack at dawn',
                    '45A01F645FC35B383552544B9BF5'))

        rc4 = RC4.RC4()
        for key, plaintext, ciphertext in vectors:
            rc4.set_key(key)
            self.assertEqual(hexlify(rc4.update(plaintext)).upper(),
                             ciphertext)

        self.assertEqual(rc4.final(), '')

    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_bad(self):
        rc4 = RC4.RC4('foo')
        self.assertNotEqual(hexlify(rc4.update('bar')).upper(), '45678')


def suite():
    return unittest.makeSuite(RC4TestCase)


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
