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

from M2Crypto import util, six


class UtilTestCase(unittest.TestCase):
    def test_py3bytes(self):
        self.assertIsInstance(util.py3bytes('test'), bytes)

    def test_py3str(self):
        self.assertIsInstance(util.py3str('test'), str)

    def test_py3bytes_str(self):
        self.assertIsInstance(util.py3bytes(u'test'), bytes)

    def test_py3str_str(self):
        self.assertIsInstance(util.py3str(u'test'), six.string_types)

    def test_py3bytes_bytes(self):
        self.assertIsInstance(util.py3bytes(b'test'), bytes)

    def test_py3str_bytes(self):
        self.assertIsInstance(util.py3str(b'test'), str)

    def test_py3bytes_bytearray(self):
        self.assertIsInstance(util.py3bytes(bytearray(b'test')), bytearray)

    def test_py3str_bytearray(self):
        self.assertIsInstance(util.py3str(bytearray(b'test')), str)

    def test_py3bytes_None(self):
        with self.assertRaises(TypeError):
            util.py3bytes(None)

    def test_py3str_None(self):
        with self.assertRaises(TypeError):
            util.py3str(None)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(UtilTestCase))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
