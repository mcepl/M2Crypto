"""M2Crypto enhancement to Python's urllib for handling 
'https' url's.

Copyright (c) 1999-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: m2urllib.py,v 1.3 2001/06/03 04:36:30 ngps Exp $'

import sys, urllib
from urllib import *

import SSL
import httpslib

DEFAULT_PROTOCOL='sslv3'

def open_https(self, url, data=None):
        self.ctx = SSL.Context(DEFAULT_PROTOCOL)
        user_passwd = None
        if type(url) is type(""):
            host, selector = splithost(url)
            if host:
                user_passwd, host = splituser(host)
                host = unquote(host)
            realhost = host
        else:
            host, selector = url
            urltype, rest = splittype(selector)
            url = rest
            user_passwd = None
            if string.lower(urltype) != 'http':
                realhost = None
            else:
                realhost, rest = splithost(rest)
                if realhost:
                    user_passwd, realhost = splituser(realhost)
                if user_passwd:
                    selector = "%s://%s%s" % (urltype, realhost, rest)
            #print "proxy via http:", host, selector
        if not host: raise IOError, ('http error', 'no host given')
        if user_passwd:
            import base64
            auth = string.strip(base64.encodestring(user_passwd))
        else:
            auth = None
        # Start here!
        if sys.version[:3] in ('2.0', '2.1'):
            #h = httpslib.HTTPS(host, ssl_context=self.ctx)
            h = httpslib.HTTPSConnection(host=host, ssl_context=self.ctx)
        elif sys.version[:3] == '1.5':
            h = httpslib.HTTPS(self.ctx, host)
        else:
            raise RuntimeError, 'unsupported Python version'
        # Stop here!
        if data is not None:
            h.putrequest('POST', selector)
            h.putheader('Content-type', 'application/x-www-form-urlencoded')
            h.putheader('Content-length', '%d' % len(data))
        else:
            h.putrequest('GET', selector)
        if auth: h.putheader('Authorization', 'Basic %s' % auth)
        if realhost: h.putheader('Host', realhost)
        for args in self.addheaders: apply(h.putheader, args)
        h.endheaders()
        if data is not None:
            h.send(data + '\r\n')
        # Here again!
        if sys.version[:3] in ('2.0', '2.1'):
            resp = h.getresponse()
            fp = resp.fp
            return urllib.addinfourl(fp, {}, "https:" + url)
        elif sys.version[:3] == '1.5':
            errcode, errmsg, headers = h.getreply()
            fp = h.getfile()
            if errcode == 200:
                return urllib.addinfourl(fp, headers, "https:" + url)
            else:
                if data is None:
                    return self.http_error(url, fp, errcode, errmsg, headers)
                else:
                    return self.http_error(url, fp, errcode, errmsg, headers, data)
        else:
            raise RuntimeError, 'unsupported Python version'
        # Stop again.

# Minor brain surgery. 
URLopener.open_https = open_https
 

