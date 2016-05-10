#!/usr/bin/env python

"""Unit tests for M2Crypto.BIO.MemoryBuffer.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

import multiprocessing
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto.BIO import MemoryBuffer


class TimeLimitExpired(Exception):
    pass


def time_limit(timeout, func, exc_msg, *args, **kwargs):
    class FuncProc(multiprocessing.Process):
        def __init__(self):
            multiprocessing.Process.__init__(self)
            self.result = None

        def run(self):
            self.result = func(*args, **kwargs)

    it = FuncProc()
    it.start()
    it.join(timeout)
    if it.is_alive():
        it.terminate()
        raise TimeLimitExpired(exc_msg)
    else:
        return it.result


class MemoryBufferTestCase(unittest.TestCase):

    def setUp(self):
        self.data = b'abcdef' * 64

    def tearDown(self):
        pass

    def test_init_empty(self):
        mb = MemoryBuffer()
        self.assertEqual(len(mb), 0)
        out = mb.read()
        assert out is None

    def test_init_empty_cm(self):
        with MemoryBuffer() as mb:
            self.assertEqual(len(mb), 0)
            out = mb.read()
            assert out is None

    def test_init_something(self):
        mb = MemoryBuffer(self.data)
        self.assertEqual(len(mb), len(self.data))
        out = mb.read()
        self.assertEqual(out, self.data)

    def test_init_something_result_bytes(self):
        mb = MemoryBuffer(self.data)
        self.assertEqual(len(mb), len(self.data))
        out = mb.read()
        self.assertIsInstance(out, bytes)

    def test_init_something_cm(self):
        with MemoryBuffer(self.data) as mb:
            self.assertEqual(len(mb), len(self.data))
            out = mb.read()
            self.assertEqual(out, self.data)

    def test_read_less_than(self):
        chunk = len(self.data) - 7
        mb = MemoryBuffer(self.data)
        out = mb.read(chunk)
        self.assertEqual(out, self.data[:chunk])
        self.assertEqual(len(mb), (len(self.data)) - chunk)

    def test_read_more_than(self):
        chunk = len(self.data) + 8
        mb = MemoryBuffer(self.data)
        out = mb.read(chunk)
        self.assertEqual(out, self.data)
        self.assertEqual(len(mb), 0)

    def test_write_close(self):
        mb = MemoryBuffer(self.data)
        assert mb.writeable()
        mb.write_close()
        assert mb.readable()
        with self.assertRaises(IOError):
            mb.write(self.data)
        assert not mb.writeable()

    def test_closed(self):
        mb = MemoryBuffer(self.data)
        mb.close()
        with self.assertRaises(IOError):
            mb.write(self.data)
        assert mb.readable() and not mb.writeable()

    def test_readline(self):
        # test against possible endless loop
        # http://stackoverflow.com/questions/9280550/
        timeout_secs = 10

        def run_test(*args, **kwargs):
            with MemoryBuffer(b'hello\nworld\n') as mb:
                self.assertTrue(mb.readable())
                self.assertEqual(mb.readline().rstrip(), b'hello')
                self.assertEqual(mb.readline().rstrip(), b'world')

            with MemoryBuffer(b'hello\nworld\n') as mb:
                self.assertEqual(mb.readlines(),
                                 [b'hello\n', b'world\n'])

        time_limit(timeout_secs, run_test,
                   'The readline() should not timeout!')


def suite():
    return unittest.makeSuite(MemoryBufferTestCase)


if __name__ == '__main__':
    unittest.TextTestRunner().run(suite())
