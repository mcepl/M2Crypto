"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: SSLServer.py,v 1.1 2000/02/23 15:36:44 ngps Exp $'

# Python
import socket, SocketServer

# M2Crypto
from Connection import Connection
from M2Crypto import Err, M2Crypto
m2 = M2Crypto


class SSLServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, ssl_context):
        """ 
        Superclass says: Constructor. May be extended, do not override.
        This class says: Ho-hum.
        """
        self.server_address=server_address
        self.RequestHandlerClass=RequestHandlerClass
        self.ssl_ctx=ssl_context
        self.socket=Connection(self.ssl_ctx)
        self.server_bind()
        self.server_activate()

    def handle_request(self):
        try:
            request, client_address = self.get_request()
            if self.verify_request(request, client_address):
                self.process_request(request, client_address)
        except Err.SSLError:
            self.handle_error()

    def handle_error(self):
        print '-'*40
        import traceback
        traceback.print_exc()
        print '-'*40

    #def verify_request(self, request, client_address):
    #    return self.request.verify_ok()


class ForkingSSLServer(SocketServer.ForkingMixIn, SSLServer):
    pass


class ThreadingSSLServer(SocketServer.ThreadingMixIn, SSLServer):
    pass


