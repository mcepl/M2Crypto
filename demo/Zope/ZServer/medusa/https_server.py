"""A https server built on Medusa's http_server. 

This server has been stable for my Zope needs. I used to advise
against running this in production. However, if you are
running a production Zope site over clear-text protocols,
perhaps you will derive a little extra security running this server.

Usual disclaimers apply.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: https_server.py,v 1.1 2000/02/01 15:20:59 ngps Exp $'

import asyncore
import asynchat
import http_server
import socket
import sys

from M2Crypto import SSL

VERSION_STRING='0.03-Zope-2.1.3'

class https_channel(http_server.http_channel):

    def __init__(self, server, conn, addr):
        http_server.http_channel.__init__(self, server, conn, addr)
        self.peer_found=0

    def send(self, data):
        result=self.socket._write_nbio(data)
        #print self, 'send:', result
        if result<=0:
            return 0
        else:
            self.server.bytes_out.increment(result)
            return result

    def recv(self, buffer_size):
        result=self.socket._read_nbio(buffer_size)
        #print self, 'recv:', 
        if result is None:
            #print '<nothing, try again>'
            return ''
        elif result=='':
            #print '<nothing, socket closed>'
            return ''
        else:
            #print result
            self.server.bytes_in.increment(len(result))
            return result

    def find_peer(self):
        peer=self.socket.get_peer_cert()
        if peer is not None:
            self.peer_found=1
            self.server.logger.log(self.addr, peer.as_text())


class https_server(http_server.http_server):

    SERVER_IDENT='M2Crypto HTTPS Server (v%s)' % VERSION_STRING

    channel_class=https_channel

    def __init__(self, ip, port, ssl_ctx, resolver=None, logger_object=None):
        http_server.http_server.__init__(self, ip, port, resolver, logger_object)
        sys.stdout.write(self.SERVER_IDENT)
        self.ssl_ctx=ssl_ctx
        
    def handle_accept(self):
        # Cribbed from http_server.
        self.total_clients.increment()
        try:
            conn, addr = self.accept()
        except socket.error:
            # linux: on rare occasions we get a bogus socket back from
            # accept.  socketmodule.c:makesockaddr complains that the
            # address family is unknown.  We don't want the whole server
            # to shut down because of this.
            sys.log_info ('warning: server accept() threw an exception', 'warning')
            return
        except TypeError:
                # unpack non-sequence.  this can happen when a read event
                # fires on a listening socket, but when we call accept()
                # we get EWOULDBLOCK, so dispatcher.accept() returns None.
                # Seen on FreeBSD3.
                self.log_info ('warning: server accept() threw EWOULDBLOCK', 'warning')
                return
        

        # Turn the vanilla socket into an SSL connection.
        ssl_conn=SSL.Connection(self.ssl_ctx, conn)
        ssl_conn._setup_ssl(addr)
        ssl_conn.accept_ssl()
        self.channel_class(self, ssl_conn, addr)

    def writeable(self):
        return 0

