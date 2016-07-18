#!/usr/bin/env python

"""PGP test program.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

from io import BytesIO
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import EVP, PGP, Rand, six


@unittest.skipIf(
    six.PY3,
    'IGNORED for python3 porting effort as PGP module is unmaintained ' +
    'and not well covered by tests')
class PGPTestCase(unittest.TestCase):

    def test_simple(self):
        pkr = PGP.load_pubring('tests/pubring.pgp')
        daft = pkr['daft']
        daft_pkt = daft._pubkey_pkt.pack()
        s1 = EVP.MessageDigest('sha1')
        s1.update(daft_pkt)
        s1f = repr(s1.final())

        buf = BytesIO(daft_pkt)
        ps = PGP.PacketStream(buf)
        dift_pkt = ps.read()
        s2 = EVP.MessageDigest('sha1')
        s2.update(dift_pkt.pack())
        s2f = repr(s2.final())

        self.assertEqual(s1f, s2f)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(PGPTestCase))
    return suite


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
