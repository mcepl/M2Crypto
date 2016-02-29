from __future__ import absolute_import, print_function

"""M2Crypto enhancement to Python's urllib for handling
'https' url's.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

import string
import urllib

from M2Crypto import SSL
from M2Crypto import httpslib

from urllib import *  # noqa for other modules to import

DEFAULT_PROTOCOL = 'sslv23'


def open_https(self, url, data=None, ssl_context=None):
    if ssl_context is not None and isinstance(ssl_context, SSL.Context):
        self.ctx = ssl_context
    else:
        self.ctx = SSL.Context(DEFAULT_PROTOCOL)
    user_passwd = None
    if isinstance(url, basestring):
        host, selector = urllib.splithost(url)
        if host:
            user_passwd, host = urllib.splituser(host)
            host = urllib.unquote(host)
        realhost = host
    else:
        host, selector = url
        urltype, rest = urllib.splittype(selector)
        url = rest
        user_passwd = None
        if string.lower(urltype) != 'http':
            realhost = None
        else:
            realhost, rest = urllib.splithost(rest)
            if realhost:
                user_passwd, realhost = urllib.splituser(realhost)
            if user_passwd:
                selector = "%s://%s%s" % (urltype, realhost, rest)
        # print("proxy via http:", host, selector)
    if not host:
        raise IOError('http error', 'no host given')
    if user_passwd:
        import base64
        auth = string.strip(base64.encodestring(user_passwd))
    else:
        auth = None
    # Start here!
    h = httpslib.HTTPSConnection(host=host, ssl_context=self.ctx)
    # h.set_debuglevel(1)
    # Stop here!
    if data is not None:
        h.putrequest('POST', selector)
        h.putheader('Content-type', 'application/x-www-form-urlencoded')
        h.putheader('Content-length', '%d' % len(data))
    else:
        h.putrequest('GET', selector)
    if auth:
        h.putheader('Authorization', 'Basic %s' % auth)
    for args in self.addheaders:
        apply(h.putheader, args)
    h.endheaders()
    if data is not None:
        h.send(data + '\r\n')
    # Here again!
    resp = h.getresponse()
    fp = resp.fp
    return urllib.addinfourl(fp, resp.msg, "https:" + url)
    # Stop again.

# Minor brain surgery.
urllib.URLopener.open_https = open_https
