"""M2Crypto enhancement to Python's httplib.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: httpslib.py,v 1.1 1999/09/12 14:33:33 ngps Exp $'

import httplib
import string

import SSL

HTTPS_PORT=443

class HTTPS(httplib.HTTP):
	def __init__(self, ssl_context, host='', port=None):
		self.debuglevel=0
		self.file=None
		self.ssl_ctx=ssl_context
		if host:
			self.connect(host, port)

	def connect(self, host, port=443):
		# Cribbed from httplib.HTTP.
		if not port:
			i = string.find(host, ':')
			if i >= 0:
				host, port = host[:i], host[i+1:]
				try: port = string.atoi(port)
				except string.atoi_error:
					raise socket.error, "nonnumeric port"
		if not port: port = HTTPS_PORT
		self.sock = SSL.Connection(self.ssl_ctx)
		if self.debuglevel > 0: print 'connect:', (host, port)
		self.sock.connect((host, port))


