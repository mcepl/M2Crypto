"""M2Crypto support for Python 1.5.2 and Python 2.x's httplib. 

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import string, sys
from httplib import *
import SSL

if sys.version[0] == '2':
    
    if sys.version_info[:2] > (2, 0):
        # In 2.1 and above, httplib exports "HTTP" only.
        from httplib import HTTPConnection, HTTPS_PORT

    class HTTPSConnection(HTTPConnection):
    
        """
        This class allows communication via SSL using M2Crypto.
        """
    
        default_port = HTTPS_PORT
    
        if sys.version_info[:3] > (2, 2, 1):
        
            # 2.2.2 and above have the 'strict' param.
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

        else:
            def __init__(self, host, port=None, **ssl):
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
                HTTPConnection.__init__(self, host, port)
    
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
            # Long-running callers beware leakage.
            #
            # 05-Jan-2002: This module works with Python 2.2,
            # but I've not investigated if the above conditions
            # remain.
            pass


    class HTTPS(HTTP):
        
        _connection_class = HTTPSConnection
    
        if sys.version_info[:3] > (2, 2, 1):
            # 2.2.2 and above have the 'strict' param.            
            def __init__(self, host='', port=None, strict=None, **ssl):
                HTTP.__init__(self, host, port, strict)
                try:
                    self.ssl_ctx = ssl['ssl_context']
                except KeyError:
                    self.ssl_ctx = SSL.Context('sslv23')
                assert isinstance(self._conn, HTTPSConnection)
                self._conn.ssl_ctx = self.ssl_ctx

        else:
            def __init__(self, host='', port=None, **ssl):
                HTTP.__init__(self, host, port)
                try:
                    self.ssl_ctx = ssl['ssl_context']
                except KeyError:
                    self.ssl_ctx = SSL.Context('sslv23')
                assert isinstance(self._conn, HTTPSConnection)
                self._conn.ssl_ctx = self.ssl_ctx


elif sys.version[:3] == '1.5':

    class HTTPS(HTTP):
    
        def __init__(self, ssl_context, host='', port=None):
            assert isinstance(ssl_context, SSL.Context)
            self.debuglevel=0
            self.file=None
            self.ssl_ctx=ssl_context
            if host:
                self.connect(host, port)
    
        def connect(self, host, port=None):
            # Cribbed from httplib.HTTP.
            if not port:
                i = string.find(host, ':')
                if i >= 0:
                    host, port = host[:i], host[i+1:]
                    try: port = string.atoi(port)
                    except string.atoi_error:
                        raise socket.error, "nonnumeric port"
            if not port: port = HTTPS_PORT
            self.sock = SSL.Connection(self.ssl_ctx)
            if self.debuglevel > 0: print 'connect:', (host, port)
            self.sock.connect((host, port))


