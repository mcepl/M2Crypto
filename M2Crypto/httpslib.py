"""M2Crypto support for Python 1.5.2 and Python 2.x's httplib. 

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

import string, sys
from httplib import *
from httplib import HTTPS_PORT # This is not imported with just '*'
import SSL

class HTTPSConnection(HTTPConnection):

    """
    This class allows communication via SSL using M2Crypto.
    """

    default_port = HTTPS_PORT

    def __init__(self, host, port=None, strict=None, **ssl):
        keys = ssl.keys()
        try: 
            keys.remove('key_file')
        except ValueError:
            pass
        try:
            keys.remove('cert_file')
        except ValueError:
            pass
        try:
            keys.remove('ssl_context')
        except ValueError:
            pass
        if keys:
            raise IllegalKeywordArgument()
        try:
            self.ssl_ctx = ssl['ssl_context']
            assert isinstance(self.ssl_ctx, SSL.Context)
        except KeyError:
            self.ssl_ctx = SSL.Context('sslv23')
        HTTPConnection.__init__(self, host, port, strict)

    def connect(self):
        self.sock = SSL.Connection(self.ssl_ctx)
        self.sock.connect((self.host, self.port))

    def close(self):
        # This kludges around line 545 of httplib.py,
        # which closes the connection in this object;
        # the connection remains open in the response
        # object.
        #
        # M2Crypto doesn't close-here-keep-open-there,
        # so, in effect, we don't close until the whole 
        # business is over and gc kicks in.
        #
        # XXX Long-running callers beware leakage.
        #
        # XXX 05-Jan-2002: This module works with Python 2.2,
        # XXX but I've not investigated if the above conditions
        # XXX remain.
        pass


class HTTPS(HTTP):
    
    _connection_class = HTTPSConnection

    def __init__(self, host='', port=None, strict=None, **ssl):
        HTTP.__init__(self, host, port, strict)
        try:
            self.ssl_ctx = ssl['ssl_context']
        except KeyError:
            self.ssl_ctx = SSL.Context('sslv23')
        assert isinstance(self._conn, HTTPSConnection)
        self._conn.ssl_ctx = self.ssl_ctx
