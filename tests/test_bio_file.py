#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import unittest
import M2Crypto
from M2Crypto.BIO import File, openfile
import os, sys

class FileTestCase(unittest.TestCase):

    def setUp(self):
        self.data = 'abcdef' * 64
        if sys.version[0] == '2' and sys.platform != 'win32':
            self.fname = os.tmpnam()
        elif sys.version[:3] == '1.5' or sys.platform == 'win32':
            import tempfile
            self.fname = tempfile.mktemp()

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
    # Python 2.2 warns that os.tmpnam() is unsafe.
    try:
        import warnings
        warnings.filterwarnings('ignore')
    except ImportError:
        pass
    return unittest.makeSuite(FileTestCase, 'check_')
    

if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())

