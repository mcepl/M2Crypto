"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: ssl_dispatcher.py,v 1.2 2000/04/01 14:55:32 ngps Exp $'

# Python
import asyncore, socket

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

    def recv(self, size=4096):
        return self.socket.recv(size)

    def send(self, buffer):
        return self.socket.send(buffer)

