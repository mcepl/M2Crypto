#!/usr/bin/env python

"""A forking SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-forking.py,v 1.1 1999/09/12 09:24:57 ngps Exp $'

import SocketServer
from M2Crypto import SSL

class ssl_echo_handler(SocketServer.BaseRequestHandler):

	buffer='Ye Olde Forking Echo Servre\r\n'

	def handle(self):
		self.request.write(self.buffer)
		while 1:
			buf=self.request.read()
			if not buf:
				break
			self.request.write(buf)	

	def finish(self):
		self.request.close()

if __name__=='__main__':
	ctx=SSL.Context('sslv23')
	ctx.load_cert('server.pem')
	s=SSL.ForkingSSLServer(('', 9999), ssl_echo_handler, ctx)
	s.serve_forever()	

