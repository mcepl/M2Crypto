#!/usr/bin/env python

"""A simple iterative SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-iterative.py,v 1.2 1999/10/01 16:13:02 ngps Exp $'

from M2Crypto import SSL
import echod_lib

class ssl_echo_handler(echod_lib.ssl_echo_handler):
    buffer='Ye Olde One-At-A-Time Echo Servre\r\n'


if __name__=='__main__':
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', SSL.verify_peer)
    s=SSL.SSLServer(('', 9999), ssl_echo_handler, ctx)
    s.serve_forever()   

