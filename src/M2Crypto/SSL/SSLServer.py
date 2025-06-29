
"""SSLServer

Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved."""


# M2Crypto
from M2Crypto.SSL.Connection import Connection
from M2Crypto.SSL.Context import Context  # noqa
from M2Crypto import util  # noqa
from socketserver import (
    BaseRequestHandler,
    BaseServer,
    TCPServer,
    ThreadingMixIn,
)
import os

if os.name != 'nt':
    from socketserver import ForkingMixIn
from socket import socket  # noqa
from typing import Union  # noqa

__all__ = ['SSLServer', 'ForkingSSLServer', 'ThreadingSSLServer']


class SSLServer(TCPServer):
    def __init__(
        self,
        server_address: util.AddrType,
        RequestHandlerClass: BaseRequestHandler,
        ssl_context: Context,  # noqa
        bind_and_activate: bool = True,
    ) -> None:
        """
        Superclass says: Constructor. May be extended, do not override.
        This class says: Ho-hum.
        """
        BaseServer.__init__(self, server_address, RequestHandlerClass)
        self.ssl_ctx = ssl_context
        self.socket = Connection(self.ssl_ctx)
        if bind_and_activate:
            self.server_bind()
            self.server_activate()

    def handle_request(self) -> None:
        from M2Crypto.SSL import SSLError

        request = None
        client_address = None
        try:
            request, client_address = self.get_request()
            if self.verify_request(request, client_address):
                self.process_request(request, client_address)
        except SSLError:
            self.handle_error(request, client_address)

    def handle_error(
        self,
        request: Union[socket, Connection],
        client_address: util.AddrType,
    ) -> None:
        print('-' * 40)
        import traceback

        traceback.print_exc()
        print('-' * 40)


class ThreadingSSLServer(ThreadingMixIn, SSLServer):
    pass


if os.name != 'nt':

    class ForkingSSLServer(ForkingMixIn, SSLServer):
        pass
