#!/usr/bin/env python

"""A multi-threading SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

# XXX Doesn't quite work yet.

RCS_id='$Id: echod-threading.py,v 1.1 1999/09/12 09:25:16 ngps Exp $'

import SocketServer
from M2Crypto import SSL

class ssl_echo_handler(SocketServer.BaseRequestHandler):

	buffer='Ye Olde Threading Echo Servre\r\n'

	def handle(self):
		print self.request.get_state()
		sent=self.request.send(self.buffer)
		while 1:
			buf=self.request.recv(1024)
			if not buf:
				break
			self.request.send(buf)	

	def finish(self):
		self.request.close()

if __name__=='__main__':
	ctx=SSL.Context('sslv23')
	ctx.load_cert('server.pem')
	s=SSL.ThreadingSSLServer(('', 9999), ssl_echo_handler, ctx)
	s.serve_forever()	

