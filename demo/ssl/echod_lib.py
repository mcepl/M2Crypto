#!/usr/bin/env python

"""Support routines for the various SSL 'echo' servers.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod_lib.py,v 1.1 1999/10/01 16:13:24 ngps Exp $'

import SocketServer
from M2Crypto import SSL

def init_context(protocol, certfile, cafile, verify, verify_depth=10):
    ctx=SSL.Context(protocol)
    ctx.load_cert(certfile)
    ctx.load_verify_location(cafile)
    ctx.load_client_CA(cafile)
    ctx.set_verify(verify, verify_depth)
    return ctx

class ssl_echo_handler(SocketServer.BaseRequestHandler):

    buffer='Ye Olde Echo Servre'

    def handle(self):
        self.get_peer()
        self.request.write(self.buffer)
        while 1:
            buf=self.request.read()
            if not buf:
                break
            self.request.write(buf) 

    def finish(self):
        self.request.close()

    def get_peer(self):
        while 1:
            peer=self.request.get_peer_cert()
            if peer is not None:
                print peer.as_text()
                break


