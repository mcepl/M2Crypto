#!/usr/local/bin/python -O
from __future__ import print_function
"""Implements a [hopefully] non-blocking SSL Dispatcher on top of M2Crypto.

   Written by Ilya Etingof <ilya@glas.net>, 05/2001
"""
import asyncore  # type: ignore # https://github.com/python/typeshed/issues/356
import socket

# M2Crypto
from M2Crypto import SSL  # type: ignore # we are not in proper directory


class NBConnection(SSL.Connection):
    """Functional equivalent of SSL.Connection class.

    Facilitates possibly delayed socket.connect() and socket.accept()
       termination.
    """
    def __init__(self, ctx, sock):
        SSL.Connection.__init__(self, ctx, sock)

    def connect(self, addr):
        self._setup_ssl(addr)
        # FIXME SSL.Connection doesn't have _check_ssl_return method
        return self._check_ssl_return(SSL.m2.ssl_connect(self.ssl))

    def accept(self, addr):
        self._setup_ssl(addr)
        self.accept_ssl()


class Dispatcher(asyncore.dispatcher_with_send):
    """A non-blocking SSL Dispatcher that mimics the asyncode.dispatcher API"""
    def __init__(self, cert, key, sock=None, serving=None):
        asyncore.dispatcher_with_send.__init__(self)

        self.__serving = serving

        # XXX
        if sock:
            if self.__serving:
                self.set_socket(sock)
        else:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)

        self.ctx = SSL.Context()
        self.ctx.set_verify(SSL.verify_none, 10)
        self.ctx.load_cert(cert, key)
        self.ctx.set_info_callback()

        self.ssl = NBConnection(self.ctx, self.socket)
        self.peer = None

        self.__output = ''
        self.__want_write = 1

    #
    # The following are asyncore overloaded methods
    #

    def handle_connect(self):
        """Initiate SSL connection negotiation"""
        if self.__serving:
            self.ssl.accept(self.addr)

            self.peer = self.ssl.get_peer_cert()

            self.handle_ssl_accept()

        else:
            self.ssl.connect(self.addr)

            self.handle_ssl_connect()

    def handle_read(self):
        """Read user and/or SSL protocol data from SSL connection"""
        ret = self.ssl._read_nbio()

        if ret:
            self.handle_ssl_read(ret)
        else:
            # Assume write is wanted
            self.__want_write = 1

    def handle_write(self):
        """Write pending user or SSL protocol data down to SSL connection"""
        self.__want_write = 0

        ret = self.ssl._write_nbio(self.__output)

        if ret < 0:
            try:
                err = SSL.m2.ssl_get_error(self.ssl.ssl, ret)

            except SSL.SSLError:
                return

            if err == SSL.m2.ssl_error_want_write:
                self.__want_write = 1
        else:
            self.__output = self.__output[ret:]

    def writable(self):
        """Indicate that write is desired.

        Happens if there's some user and/or SSL protocol data.
        """
        if self.__output or self.__want_write:
            return 1

        return self.ssl_writable()

    def handle_close(self):
        """Shutdown SSL connection."""
        self.ssl = None

        self.ctx = None
        self.close()

        self.handle_ssl_close()

    def handle_error(self, *info):
        """A trap for asyncore errors"""
        self.handle_ssl_error(info)

    #
    # The following are ssl.dispatcher API
    #

    def ssl_connect(self, server):
        """Initiate SSL connection"""
        self.connect(server)

    def ssl_write(self, data):
        """Write data to SSL connection"""
        self.__output = self.__output + data

    def ssl_close(self):
        """Close SSL connection"""
        self.handle_close()

    def handle_ssl_connect(self):
        """Invoked on SSL connection establishment (whilst in Client mode)"""
        print('Unhandled handle_ssl_connect()')

    def handle_ssl_accept(self):
        """Invoked on SSL connection establishment (whilst in server mode)"""
        print('Unhandled handle_ssl_accept()')

    def handle_ssl_read(self, data):
        """Invoked on new data arrival to SSL connection"""
        print('Unhandled handle_ssl_read event')

    def handle_ssl_close(self):
        """Invoked on SSL connection termination"""
        pass

    def ssl_writable(self):
        """Invoked prior to every select() call"""
        return 0

if __name__ == '__main__':
    """Give it a test run"""
    class Client(Dispatcher):
        """SSL Client class"""
        def __init__(self, cert, key):
            Dispatcher.__init__(self, cert, key)

        def handle_ssl_read(self, data):
            print(data)
            self.ssl_write('test write')

    ssl = Client('test.cert', 'test.key')
    ssl.ssl_connect(('localhost', 7777))

    asyncore.loop()
