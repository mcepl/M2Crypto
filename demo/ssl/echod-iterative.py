#!/usr/bin/env python

"""A simple iterative SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-iterative.py,v 1.4 2000/08/23 15:46:21 ngps Exp $'

from M2Crypto import Rand, SSL, threading
import echod_lib

class ssl_echo_handler(echod_lib.ssl_echo_handler):
    buffer='Ye Olde One-At-A-Time Echo Servre\r\n'


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    threading.init()
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', \
        #SSL.verify_peer | SSL.verify_fail_if_no_peer_cert)
        SSL.verify_none)
    ctx.set_tmp_dh('dh1024.pem')
    s=SSL.SSLServer(('', 9999), ssl_echo_handler, ctx)
    s.serve_forever()   
    threading.cleanup()
    Rand.save_file('../randpool.dat')

