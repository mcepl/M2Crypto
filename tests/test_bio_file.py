#!/usr/bin/env python2.0

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: test_bio_file.py,v 1.1 2000/11/08 14:41:35 ngps Exp $'

import unittest
import M2Crypto
from M2Crypto.BIO import File, openfile
import os

class FileTestCase(unittest.TestCase):

    def setUp(self):
        self.data = 'abcdef' * 64
        self.fname = os.tmpnam()

    def tearDown(self):
        try:
            os.unlink(self.fname)
        except OSError:
            pass

    def check_openfile_rb(self):
        # First create the file using Python's open().
        f = open(self.fname, 'wb')
        f.write(self.data)
        f.close()
        # Now open the file using M2Crypto.BIO.openfile().
        f = openfile(self.fname, 'rb')
        data = f.read(len(self.data))
        assert data == self.data

    def check_openfile_wb(self):
        # First create the file using M2Crypto.BIO.openfile().
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        # Now open the file using Python's open().
        f = open(self.fname, 'rb')
        data = f.read(len(self.data))
        assert data == self.data

    def check_closed(self):
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        self.assertRaises(IOError, f.write, self.data)

    def check_use_pyfile(self):
        # First create the file.
        f = open(self.fname, 'wb')
        f2 = File(f)
        f2.write(self.data)
        f2.close()
        # Now read the file.
        f = open(self.fname, 'rb')
        data = f.read(len(self.data))
        assert data == self.data


def suite():
    return unittest.makeSuite(FileTestCase, 'check_')
    

if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

