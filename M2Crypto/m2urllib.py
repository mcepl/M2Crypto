"""M2Crypto enhancement to Python's urllib for handling 'https' url's.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved.

Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam, 
The Netherlands. """

RCS_id='$Id: m2urllib.py,v 1.1 1999/09/12 14:34:41 ngps Exp $'

from urllib import *

import SSL
import httpslib

DEFAULT_PROTOCOL='sslv3'

# Cut-&-pasted almost verbatim from urllib's open_http().
# Achtung: following code indents by space, _not_ by tabs.
def open_https(self, url, data=None):
        self.ctx=SSL.Context(DEFAULT_PROTOCOL)
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
        # Here!
        h = httpslib.HTTPS(self.ctx, host)
        #h.debuglevel=1
        # Here!
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
        errcode, errmsg, headers = h.getreply()
        fp = h.getfile()
        if errcode == 200:
            return addinfourl(fp, headers, "http:" + url)
        else:
            if data is None:
                return self.http_error(url, fp, errcode, errmsg, headers)
            else:
                return self.http_error(url, fp, errcode, errmsg, headers, data)

# Minor brain surgery. 
URLopener.open_https=open_https

