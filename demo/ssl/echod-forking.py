#!/usr/bin/env python

"""A forking SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-forking.py,v 1.2 1999/10/01 16:11:48 ngps Exp $'

from M2Crypto import SSL
import echod_lib

class ssl_echo_handler(echod_lib.ssl_echo_handler):
    buffer='Ye Olde Forking Echo Servre\r\n'


if __name__=='__main__':
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', SSL.verify_peer)
    s=SSL.ForkingSSLServer(('', 9999), ssl_echo_handler, ctx)
    s.serve_forever()   

