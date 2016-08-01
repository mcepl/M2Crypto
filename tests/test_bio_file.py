#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.File.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import logging
import os
import tempfile
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto.BIO import File, openfile

log = logging.getLogger(__name__)


class FileTestCase(unittest.TestCase):

    def setUp(self):
        self.data = b'abcdef' * 64
        self.fd, self.fname = tempfile.mkstemp()

        # mvyskocil: to check leaks of file descriptors
        self._proc = "/proc/{0}/fd/".format(os.getpid())
        self.max_fd = self.mfd()

    # FIXME: this indeed does work on Linux and probably other *nixes,
    # but definitelly
    #       not on windows, add a fallback method, like
    #       os.fdopen().fileno()-1
    def mfd(self):
        return int(os.listdir(self._proc)[-1])

    def tearDown(self):

        self.assertEqual(
            self.max_fd, self.mfd(),
            "last test did not close all file descriptors properly")

        try:
            os.close(self.fd)
        except OSError:
            pass

    def test_openfile_rb(self):
        # First create the file using Python's open().
        with open(self.fname, 'wb') as f:
            f.write(self.data)

        # Now open the file using M2Crypto.BIO.openfile().
        with openfile(self.fname, 'rb') as f:
            data = f.read(len(self.data))

        self.assertEqual(data, self.data)

    def test_openfile_wb(self):
        # First create the file using M2Crypto.BIO.openfile().
        with openfile(self.fname, 'wb') as f:
            f.write(self.data)

        # Now open the file using Python's open().
        with open(self.fname, 'rb') as f:
            data = f.read(len(self.data))

        self.assertEqual(data, self.data)

    def test_closed(self):
        f = openfile(self.fname, 'wb')
        f.write(self.data)
        f.close()
        with self.assertRaises(IOError):
            f.write(self.data)

    def test_use_pyfile(self):
        # First create the file.
        with open(self.fname, 'wb') as f:
            f2 = File(f)
            f2.write(self.data)
            f2.close()

        # Now read the file.
        with open(self.fname, 'rb') as f:
            in_data = f.read(len(self.data))

        self.assertEqual(len(in_data), len(self.data))
        self.assertEqual(in_data, self.data)

    def test_readline(self):
        with open(self.fname, 'w') as f:
            f.write('hello\nworld\n')
        with openfile(self.fname, 'r') as f:
            self.assertTrue(f.readable())
            self.assertEqual(f.readline(), 'hello\n')
            self.assertEqual(f.readline(), 'world\n')
        with openfile(self.fname, 'r') as f:
            self.assertEqual(f.readlines(), ['hello\n', 'world\n'])

    def test_tell_seek(self):
        with open(self.fname, 'w') as f:
            f.write('hello world')
        with openfile(self.fname, 'r') as f:
            # Seek absolute
            f.seek(6)
            self.assertEqual(f.tell(), 6)


def suite():
    return unittest.makeSuite(FileTestCase)


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
