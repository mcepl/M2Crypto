#!/usr/bin/env python

"""Another multi-threading SSL 'echo' server.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-thread.py,v 1.1 2000/08/23 15:49:53 ngps Exp $'

from M2Crypto import DH, Rand, SSL, threading
import echod_lib

import thread
from socket import *

buffer='Ye Newe Threading Echo Servre\r\n'

def echo_handler(sslctx, sock, addr):
    sslconn = SSL.Connection(sslctx, sock)
    sslconn._setup_ssl(addr)
    sslconn.accept_ssl()
    sslconn.write(buffer) 
    while 1:
        buf = sslconn.read()
        if not buf:
            break
        sslconn.write(buf) 
    sslconn.set_shutdown(SSL.SSL_RECEIVED_SHUTDOWN | SSL.SSL_SENT_SHUTDOWN)
    sslconn.close()


if __name__=='__main__':
    threading.init()
    Rand.load_file('../randpool.dat', -1) 
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', 
        SSL.verify_none)
        #SSL.verify_peer | SSL.verify_fail_if_no_peer_cert)
    ctx.set_tmp_dh('dh1024.pem')
    sock = socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind('', 9999)
    sock.listen(5)
    while 1:
        conn, addr = sock.accept()
        thread.start_new_thread(echo_handler, (ctx, conn, addr))
    Rand.save_file('../randpool.dat')
    threading.cleanup()

