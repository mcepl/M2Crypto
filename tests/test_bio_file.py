#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import os, sys
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import M2Crypto
from M2Crypto.BIO import File, openfile

class FileTestCase(unittest.TestCase):

    def setUp(self):
        self.data = b'abcdef' * 64
        self.fd, self.fname = tempfile.mkstemp()
        
        #mvyskocil: to check leaks of file descriptors
        self._proc = "/proc/{}/fd/".format(os.getpid())
        self.max_fd = self.mfd()

    #FIXME: this indeed does work on Linux and probably other *nixes, but definitelly
    #       not on windows, add a fallback method, like os.fdopen().fileno()-1
    def mfd(self):
        return int(os.listdir(self._proc)[-1])

    def tearDown(self):

        self.assertEqual(self.max_fd, self.mfd(), "last test did not close all file descriptors properly")

        try:
            os.close(self.fd)
        except OSError:
            pass

    def test_openfile_rb(self):
        # First create the file using Python's open().
        f = open(self.fname, 'wb')
        f.write(self.data)
        f.close()
        # Now open the file using M2Crypto.BIO.openfile().
        f = openfile(self.fname, 'rb')
        data = f.read(len(self.data))
        f.close()
        self.assertEqual(data, self.data)

    def test_openfile_wb(self):
        # First create the file using M2Crypto.BIO.openfile().
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        # Now open the file using Python's open().
        f = open(self.fname, 'rb')
        data = f.read(len(self.data))
        f.close()
        self.assertEqual(data, self.data)

    def test_closed(self):
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        with self.assertRaises(IOError):
            f.write(self.data)

    def test_use_pyfile(self):
        # First create the file.
        f = open(self.fname, 'wb')
        f2 = File(f)
        f2.write(self.data)
        f2.close()
        # Now read the file.
        f = open(self.fname, 'rb')
        data = f.read(len(self.data))
        f.close()
        self.assertEqual(data, self.data)


def suite():
    return unittest.makeSuite(FileTestCase)


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
