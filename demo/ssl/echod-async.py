#!/usr/bin/env python

"""An SSL 'echo' server, using asynchronous socket I/O.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-async.py,v 1.2 2000/04/17 15:55:17 ngps Exp $'

import asyncore
import errno
import socket
import time

from M2Crypto import Err, DH, Rand, SSL
import echod_lib

class ssl_echo_channel(SSL.ssl_dispatcher):

    buffer='Ye Olde Echo Servre\r\n'

    def __init__(self, conn):
        SSL.ssl_dispatcher.__init__(self, conn)
        self.rc = 1
        self.wc = 1
        self.peer = None

    def handle_connect(self):
        #print 'bogus: handle_connect'
        pass

    def handle_close(self):
        self.close()

    def writeable(self):
        time.sleep(1)
        return len(self.buffer) > 0
 
    def handle_write(self):
        self.wc = self.wc + 1
        if self.peer is None:
            self.peer = self.get_peer_cert()
            if self.peer is not None:
                print 'wc =', self.wc
                print self.peer.get_subject()
        try:
            n=self.send(self.buffer)
            if n == -1:
                pass
            elif n == 0:
                self.handle_close()
            else:
                self.buffer=self.buffer[n:]
        except:
            self.close()

    def readable(self):
        #time.sleep(1)
        return 1

    def handle_read(self):
        self.rc = self.rc + 1
        if self.peer is None:
            self.peer = self.get_peer_cert()
            if self.peer is not None:
                print 'rc =', self.rc
                print self.peer.get_subject()
        try:
            blob=self.recv()
            if blob is None:
                pass
            elif blob == '':
                self.handle_close() 
            else: 
                self.buffer = self.buffer + blob        
        except:
            self.close()


class ssl_echo_server(SSL.ssl_dispatcher):

    channel_class=ssl_echo_channel

    def __init__(self, addr, port, ssl_context):
        SSL.ssl_dispatcher.__init__(self)
        self.create_socket(ssl_context)
        self.set_reuse_addr()
        self.socket.setblocking(0)
        self.bind((addr, port))
        self.listen(5)
        self.ssl_ctx=ssl_context
    
    def handle_accept(self):
        try:
            sock, addr = self.socket.accept()
            self.channel_class(sock)
        except:
            print '-'*40
            import traceback
            traceback.print_exc()
            print '-'*40
            return
#        if sock.verify_ok():
#            self.channel_class(sock)
#        else:
#            v = sock.get_verify_result()
#            print 'peer verification failed:', Err.get_x509_verify_error(v)
#            sock.close()

    def writeable(self):
        return 0


if __name__=='__main__':
    Rand.load_file('../randpool.dat', -1) 
    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', \
        #SSL.verify_none)
        SSL.verify_peer | SSL.verify_fail_if_no_peer_cert)
    ctx.set_tmp_dh('dh1024.pem')
    ssl_echo_server('', 9999, ctx)
    asyncore.loop()
    Rand.save_file('../randpool.dat')

