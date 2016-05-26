#!/usr/bin/env python

"""Unit tests for M2Crypto.AuthCookie.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import logging
import time
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import EVP, Rand, util
from M2Crypto.AuthCookie import AuthCookie, AuthCookieJar, mix, unmix, unmix3
from M2Crypto.six.moves.http_cookies import SimpleCookie

log = logging.getLogger(__name__)


class AuthCookieTestCase(unittest.TestCase):

    _format = 'Set-Cookie: _M2AUTH_="exp=%s&data=%s&digest=%s"'
    _token = '_M2AUTH_'

    def setUp(self):
        self.data = 'cogitoergosum'
        self.exp = time.time() + 3600
        self.jar = AuthCookieJar()

    def tearDown(self):
        pass

    def test_mix_unmix(self):
        dough = mix(self.exp, self.data)
        exp, data = unmix(dough)
        self.assertEqual(data, self.data)
        self.assertEqual(exp, self.exp)

    def test_make_cookie(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(isinstance(c, AuthCookie))
        self.assertEqual(c.expiry(), self.exp)
        self.assertEqual(c.data(), self.data)
        # Peek inside the cookie jar...
        key = self.jar._key
        mac = util.bin_to_hex(
            EVP.hmac(key, util.py3bytes(mix(self.exp, self.data)), 'sha1'))
        self.assertEqual(c.mac(), mac)
        # Ok, stop peeking now.
        cookie_str = self._format % (repr(self.exp), self.data, mac)
        self.assertEqual(c.output(), cookie_str)

    def test_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.assertTrue(c.isExpired())

    def test_not_expired(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertFalse(c.isExpired())

    def test_is_valid(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(self.jar.isGoodCookie(c))

    def test_is_invalid_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._expiry = 'this is bad'
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._data = 'this is bad'
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_is_invalid_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._mac = 'this is bad'
        self.assertFalse(self.jar.isGoodCookie(c))

    def test_mix_unmix3(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = SimpleCookie()
        s.load(c.output())
        exp, data, digest = unmix3(s[self._token].value)
        self.assertEqual(data, self.data)
        self.assertEqual(float(exp), self.exp)
        key = self.jar._key     # Peeking...
        mac = util.bin_to_hex(
            EVP.hmac(key, util.py3bytes(mix(self.exp, self.data)), 'sha1'))
        self.assertEqual(digest, mac)

    def test_cookie_str(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.assertTrue(self.jar.isGoodCookieString(c.output()))

    def test_cookie_str2(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = SimpleCookie()
        s.load(c.output())
        self.assertTrue(self.jar.isGoodCookieString(s.output()))

    def test_cookie_str_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        s = SimpleCookie()
        s.load(c.output())
        self.assertFalse(self.jar.isGoodCookieString(s.output()))

    def test_cookie_str_arbitrary_change(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        cout_str = cout[:32] + 'this is bad' + cout[32:]
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output()))

    def test_cookie_str_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        cout_str = cout[:26] + '2' + cout[27:]
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output()))

    def test_cookie_str_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        cout_str = cout[:36] + 'X' + cout[37:]
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output()))

    def test_cookie_str_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        cout_str = cout[:76] + 'X' + cout[77:]
        s = SimpleCookie()
        s.load(cout_str)
        self.assertFalse(self.jar.isGoodCookieString(s.output()))


def suite():
    return unittest.makeSuite(AuthCookieTestCase)


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
