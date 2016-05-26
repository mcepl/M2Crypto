#!/usr/bin/env python

"""Unit tests for M2Crypto.Rand.

Copyright (C) 2006 Open Source Applications Foundation (OSAF).
All Rights Reserved.
"""

import os
import warnings
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import Rand


class RandTestCase(unittest.TestCase):
    def test_bytes(self):
        with self.assertRaises(MemoryError):
            Rand.rand_bytes(-1)
        self.assertEqual(Rand.rand_bytes(0), b'')
        self.assertEqual(len(Rand.rand_bytes(1)), 1)

    def test_pseudo_bytes(self):
        with self.assertRaises(MemoryError):
            Rand.rand_pseudo_bytes(-1)
        self.assertEqual(Rand.rand_pseudo_bytes(0), (b'', 1))
        a, b = Rand.rand_pseudo_bytes(1)
        self.assertEqual(len(a), 1)
        self.assertEqual(b, 1)

    def test_file_name(self):
        if "RANDFILE" in os.environ:
            self.assertEqual(Rand.rand_file_name(),
                             os.environ["RANDFILE"])
        else:
            self.assertEqual(Rand.rand_file_name(),
                             os.path.join(os.environ["HOME"], ".rnd"))

    def test_load_save(self):
        try:
            os.remove('tests/randpool.dat')
        except OSError:
            pass
        self.assertEqual(Rand.load_file('tests/randpool.dat', -1), 0)
        self.assertEqual(Rand.save_file('tests/randpool.dat'), 1024)
        self.assertEqual(Rand.load_file('tests/randpool.dat', -1), 1024)

    def test_seed_add(self):
        self.assertIsNone(Rand.rand_seed(os.urandom(1024)))

        # XXX Should there be limits on the entropy parameter?
        self.assertIsNone(Rand.rand_add(os.urandom(2), 0.5))
        Rand.rand_add(os.urandom(2), -0.5)
        Rand.rand_add(os.urandom(2), 5000.0)

    def test_rand_status(self):
        # Although it is hard to believe we would ever get 0 (i.e., PRNG
        # hasn't enough entropy), it is a legitimate value.
        status = Rand.rand_status()
        self.assertIn(status, [0, 1],
                      'Illegal value of RAND.rand_status {0}!'.format(status))
        if status == 0:
            warnings.warn('RAND_status reports insufficient seeding of PRNG!')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RandTestCase))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
