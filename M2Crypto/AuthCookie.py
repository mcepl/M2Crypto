from __future__ import absolute_import

"""Secure Authenticator Cookies

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""

import logging
import re
import time

# M2Crypto
from M2Crypto import Rand, m2, util
from M2Crypto.six.moves.http_cookies import SimpleCookie


if util.py27plus:
    from typing import re as type_re, AnyStr, Dict, Optional, Union  # noqa

_MIX_FORMAT = 'exp=%s&data=%s&digest='
_MIX_RE = re.compile('exp=(\d+\.\d+)&data=(.+)&digest=(\S*)')

log = logging.getLogger(__name__)


def mix(expiry, data, format=_MIX_FORMAT):
    # type: (float, AnyStr, str) -> AnyStr
    return format % (repr(expiry), data)


def unmix(dough, regex=_MIX_RE):
    # type: (AnyStr, type_re) -> object
    mo = regex.match(dough)
    if mo:
        return float(mo.group(1)), mo.group(2)
    else:
        return None


def unmix3(dough, regex=_MIX_RE):
    # type: (AnyStr, type_re) -> Optional[tuple[float, AnyStr, AnyStr]]
    mo = regex.match(dough)
    if mo:
        return float(mo.group(1)), mo.group(2), mo.group(3)
    else:
        return None


_TOKEN = '_M2AUTH_'  # type: str


class AuthCookieJar:

    _keylen = 20  # type: int

    def __init__(self):
        # type: () -> None
        self._key = Rand.rand_bytes(self._keylen)

    def _hmac(self, key, data):
        # type: (bytes, str) -> str
        return util.bin_to_hex(m2.hmac(key, util.py3bytes(data), m2.sha1()))

    def makeCookie(self, expiry, data):
        # type: (float, str) -> AuthCookie
        dough = mix(expiry, data)
        return AuthCookie(expiry, data, dough, self._hmac(self._key, dough))

    def isGoodCookie(self, cookie):
        # type: (AuthCookie) -> Union[bool, int]
        assert isinstance(cookie, AuthCookie)
        if cookie.isExpired():
            return 0
        c = self.makeCookie(cookie._expiry, cookie._data)
        return (c._expiry == cookie._expiry) \
            and (c._data == cookie._data) \
            and (c._mac == cookie._mac) \
            and (c.output() == cookie.output())

    def isGoodCookieString(self, cookie_str):
        # type: (Union[dict, bytes]) -> Union[bool, int]
        c = SimpleCookie()
        c.load(cookie_str)
        if _TOKEN not in c:
            return 0
        undough = unmix3(c[_TOKEN].value)
        if undough is None:
            return 0
        exp, data, mac = undough
        c2 = self.makeCookie(exp, data)
        return (not c2.isExpired()) and (c2._mac == mac)


class AuthCookie:

    def __init__(self, expiry, data, dough, mac):
        # type: (float, str, str, str) -> None
        self._expiry = expiry
        self._data = data
        self._mac = mac
        self._cookie = SimpleCookie()
        self._cookie[_TOKEN] = '%s%s' % (dough, mac)
        self._name = '%s%s' % (dough, mac)  # XXX WebKit only.

    def expiry(self):
        # type: () -> float
        """Return the cookie's expiry time."""
        return self._expiry

    def data(self):
        # type: () -> str
        """Return the data portion of the cookie."""
        return self._data

    def mac(self):
        # type: () -> str
        """Return the cookie's MAC."""
        return self._mac

    def output(self):
        # type: () -> str
        """Return the cookie's output in "Set-Cookie" format."""
        return self._cookie.output()

    def value(self):
        # type: () -> str
        """Return the cookie's output minus the "Set-Cookie: " portion.
        """
        return self._cookie[_TOKEN].value

    def isExpired(self):
        # type: () -> bool
        """Return 1 if the cookie has expired, 0 otherwise."""
        return isinstance(self._expiry, (float, int)) and \
            (time.time() > self._expiry)

    # XXX Following methods are for WebKit only. These should be pushed
    # to WKAuthCookie.
    def name(self):
        # type: () -> str
        return self._name

    def headerValue(self):
        # type: () -> str
        return self.value()
