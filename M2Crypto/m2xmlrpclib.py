"""M2Crypto enhancement to xmlrpclib.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: m2xmlrpclib.py,v 1.1 1999/10/18 15:07:06 ngps Exp $'

from xmlrpclib import *
import httpslib, SSL

__version__='0.03'

class SSL_Transport(Transport):

    user_agent = "xmlrpc_ssl.py/%s - %s" % (__version__, Transport.user_agent)

    def __init__(self, ssl_context=None, proxy_host=None, proxy_port=8080):
        self.use_proxy=0
        if proxy_host is not None:
            self.proxy_host=proxy_host
            self.proxy_port=proxy_port
            self.use_proxy=1
        if ssl_context is None:
            self.ssl_ctx=SSL.Context('sslv23')
        else:
            self.ssl_ctx=ssl_context

    def request(self, host, handler, request_body):
        if self.use_proxy:
            h = httpslib.HTTPS(self.ssl_ctx, self.proxy_host, self.proxy_port)
        else:
            h = httpslib.HTTPS(self.ssl_ctx, host)
        req = 'https://%s%s' % (host, handler)

        # Everything that follows is as in xmlrpclib.Transport.
        h.putrequest("POST", handler)

        # required by HTTP/1.1
        h.putheader("Host", host)

        # required by XML-RPC
        h.putheader("User-Agent", self.user_agent)
        h.putheader("Content-Type", "text/xml")
        h.putheader("Content-Length", str(len(request_body)))

        h.endheaders()

        if request_body:
            h.send(request_body)

        errcode, errmsg, headers = h.getreply()

        if errcode != 200:
            raise ProtocolError(
                host + handler,
                errcode, errmsg,
                headers
                )

        return self.parse_response(h.getfile())

