#!/usr/bin/env python

"""A forking SSL 'echo' server.

Copyright (c) 1999-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-forking.py,v 1.5 2001/09/18 12:22:38 ngps Exp $'

from M2Crypto import DH, Rand, SSL
import echod_lib

class ssl_echo_handler(echod_lib.ssl_echo_handler):
    buffer='Ye Olde Forking Echo Servre\r\n'


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', SSL.verify_peer)
    ctx.set_tmp_dh('dh1024.pem')
    s=SSL.ForkingSSLServer(('', 9999), ssl_echo_handler, ctx)
    s.serve_forever()   
    Rand.save_file('../randpool.dat')

