#!/usr/bin/env python

"""An SSL 'echo' server, using asynchronous socket I/O.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-async.py,v 1.1 1999/09/12 09:24:39 ngps Exp $'

import asyncore
import errno
import socket

from M2Crypto import SSL

class ssl_echo_channel(SSL.ssl_dispatcher):

	buffer='Ye Olde Echo Servre\r\n'

	def handle_connect(self):
		pass

	def handle_close(self):
		self.close()

	def writeable(self):
		return len(self.buffer) > 0
 
	def handle_write(self):
		n=self.send(self.buffer)
		if n==-1:
			pass
		elif n==0:
			self.handle_close()
		else:
			self.buffer=self.buffer[n:]

	def readable(self):
		return 1

	def handle_read(self):
		blob=self.recv()
		if blob is None:
			pass
		elif blob=='':
			self.handle_close()	
		else: 
			self.buffer = self.buffer + blob		


class ssl_echo_server(SSL.ssl_dispatcher):

	channel_class=ssl_echo_channel

	def __init__(self, addr, port, ssl_context):
		asyncore.dispatcher.__init__(self)
		self.create_socket(ssl_context)
		self.set_reuse_addr()
		self.socket.setblocking(0)
		self.bind((addr, port))
		self.listen(5)
	
	def handle_accept(self):
		sock, addr=self.socket.accept()
		self.channel_class(sock)

	def writeable(self):
		return 0


if __name__=='__main__':
	ctx=SSL.Context('sslv23')
	ctx.load_cert('server.pem')
	ssl_echo_server('', 9999, ctx)
	asyncore.loop()

