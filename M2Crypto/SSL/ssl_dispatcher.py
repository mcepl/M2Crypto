"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: ssl_dispatcher.py,v 1.1 2000/02/23 15:39:31 ngps Exp $'

# Python
import asyncore, socket, sys

# M2Crypto
from Connection import Connection
from M2Crypto import Err, M2Crypto
m2 = M2Crypto


class ssl_dispatcher(asyncore.dispatcher):

    def create_socket(self, ssl_context):
        self.family_and_type=socket.AF_INET, socket.SOCK_STREAM
        self.ssl_ctx=ssl_context
        self.socket=Connection(self.ssl_ctx)
        self.socket.setblocking(0)
        self.add_channel()

    def send(self, data):
        (n, err)=m2.ssl_write_nbio(self.ssl, data)
        if n==-1:
            if err==m2.ssl_error_zero_return:
                return 0
            elif err==m2.ssl_error_syscall:
                raise Err.SSLError(n, self.socket.getpeername())
            else:       # Only in non-blocking mode. 
                return -1
        else:
            if n==0:    # In non-blocking SSL, this means 'try again'.
                return 0
            else:
                return n

    def recv(self, size=4096):
        (n, blob, err)=m2.ssl_read_nbio(self.ssl, size)
        if n==-1:
            if err==m2.ssl_error_zero_return:
                return ''
            elif err in [m2.ssl_error_ssl, m2.ssl_error_syscall]:
                m2.err_print_errors_fp(sys.stderr)
                raise Err.SSLError(n, self.socket.getpeername())
            else:
                return None # XXX None is overloaded to mean 'try-again'.
        else:
            return blob


