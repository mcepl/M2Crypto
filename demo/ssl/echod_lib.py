"""Support routines for the various SSL 'echo' servers.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod_lib.py,v 1.5 2002/12/23 04:39:22 ngps Exp $'

import SocketServer
from M2Crypto import SSL

def init_context(protocol, certfile, cafile, verify, verify_depth=10):
    ctx = SSL.Context(protocol)
    ctx.load_cert(certfile)
    ctx.load_client_ca(cafile)
    ctx.load_verify_info(cafile)
    ctx.set_verify(verify, verify_depth)
    ctx.set_allow_unknown_ca(1)
    ctx.set_session_id_ctx('echod')
    ctx.set_info_callback()
    return ctx


class ssl_echo_handler(SocketServer.BaseRequestHandler):

    buffer = 'Ye Olde Echo Servre\r\n'

    def handle(self):
        peer = self.request.get_peer_cert()
        if peer is not None:
            print 'Client CA        =', peer.get_issuer().O
            print 'Client Subject   =', peer.get_subject().CN
        print 'XXX'
        x = self.request.write(self.buffer)
        print 'YYY:', x
        while 1:
            try:
                buf = self.request.read()
                if not buf:
                    break
                self.request.write(buf) 
            except SSL.SSLError, what:
                if str(what) == 'unexpected eof':
                    break
                else:
                    raise

    def finish(self):
        self.request.close()


