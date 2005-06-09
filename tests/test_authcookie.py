#!/usr/bin/env python

"""Unit tests for M2Crypto.AuthCookie.

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import Cookie, binascii, time, unittest
from M2Crypto.AuthCookie import AuthCookie, AuthCookieJar, mix, unmix, unmix3
from M2Crypto import Rand, EVP

class AuthCookieTestCase(unittest.TestCase):

    _format = 'Set-Cookie: _M2AUTH_="exp=%s&data=%s&digest=%s";'
    _token = '_M2AUTH_'

    def setUp(self):
        self.data = 'cogitoergosum'
        self.exp = time.time() + 3600
        self.jar = AuthCookieJar()

    def tearDown(self):
        pass

    def check_mix_unmix(self):
        dough = mix(self.exp, self.data)
        exp, data = unmix(dough)
        self.failUnlessEqual(data, self.data)
        self.failUnlessEqual(exp, self.exp)

    def check_make_cookie(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.failUnless(isinstance(c, AuthCookie))
        self.failUnlessEqual(c.expiry(), self.exp)
        self.failUnlessEqual(c.data(), self.data)
        # Peek inside the cookie jar...
        key = self.jar._key
        mac = binascii.b2a_base64(EVP.hmac(key, mix(self.exp, self.data), 'sha1'))[:-1]
        self.failUnlessEqual(c.mac(), mac)
        # Ok, stop peeking now.
        cookie_str = self._format % (repr(self.exp), self.data, mac)
        self.failUnlessEqual(c.output(), cookie_str)

    def check_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.failUnless(c.isExpired())

    def check_not_expired(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.failIf(c.isExpired())

    def check_is_valid(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.failUnless(self.jar.isGoodCookie(c))
        
    def check_is_invalid_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        self.failIf(self.jar.isGoodCookie(c))

    def check_is_invalid_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._expiry = 'this is bad'
        self.failIf(self.jar.isGoodCookie(c))

    def check_is_invalid_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._data = 'this is bad'
        self.failIf(self.jar.isGoodCookie(c))

    def check_is_invalid_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        c._mac = 'this is bad'
        self.failIf(self.jar.isGoodCookie(c))

    def check_mix_unmix3(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = Cookie.SmartCookie()
        s.load(c.output())
        exp, data, digest = unmix3(s[self._token].value)
        self.failUnlessEqual(data, self.data)
        self.failUnlessEqual(float(exp), self.exp)
        key = self.jar._key     # Peeking...
        mac = binascii.b2a_base64(EVP.hmac(key, mix(self.exp, self.data), 'sha1'))[:-1]
        self.failUnlessEqual(digest, mac)

    def check_cookie_str(self):
        c = self.jar.makeCookie(self.exp, self.data)
        self.failUnless(self.jar.isGoodCookieString(c.output()))

    def check_cookie_str2(self):
        c = self.jar.makeCookie(self.exp, self.data)
        s = Cookie.SmartCookie()
        s.load(c.output())
        self.failUnless(self.jar.isGoodCookieString(s.output()))

    def check_cookie_str_expired(self):
        t = self.exp - 7200
        c = self.jar.makeCookie(t, self.data)
        s = Cookie.SmartCookie()
        s.load(c.output())
        self.failIf(self.jar.isGoodCookieString(s.output()))

    def check_cookie_str_arbitrary_change(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        str = cout[:32] + 'this is bad' + cout[32:]
        s = Cookie.SmartCookie()
        s.load(str)
        self.failIf(self.jar.isGoodCookieString(s.output()))

    def check_cookie_str_changed_exp(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        str = cout[:26] + '2' + cout[27:]
        s = Cookie.SmartCookie()
        s.load(str)
        self.failIf(self.jar.isGoodCookieString(s.output()))

    def check_cookie_str_changed_data(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        str = cout[:36] + 'X' + cout[37:]
        s = Cookie.SmartCookie()
        s.load(str)
        self.failIf(self.jar.isGoodCookieString(s.output()))

    def check_cookie_str_changed_mac(self):
        c = self.jar.makeCookie(self.exp, self.data)
        cout = c.output()
        str = cout[:76] + 'X' + cout[77:]
        s = Cookie.SmartCookie()
        s.load(str)
        self.failIf(self.jar.isGoodCookieString(s.output()))


def suite():
    return unittest.makeSuite(AuthCookieTestCase, 'check_')


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1) 
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

