#!/usr/bin/env python

"""An M2Crypto implementation of OpenSSL's s_server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

# XXX Doesn't quite work yet.

RCS_id='$Id: s_server.py,v 1.1 1999/09/12 09:25:35 ngps Exp $'

from socket import *
import asyncore
import cStringIO
import getopt
import string
import sys

from M2Crypto import SSL, BIO

# s_server -www
HOST=''
PORT=4433
REQ='GET / HTTP/1.0\r\n\r\n'

class Config:
	pass

def config(args):
	options=['accept=', 'context=', 'verify=', 'Verify=', 'cert=', 'key=', \
		'dcert=', 'dkey=', 'nocert', 'crlf', 'debug', 'CApath=', 'CAfile=', \
		'quiet', 'no_tmp_rsa', 'state', 'sslv2', 'sslv3', 'tlsv1', \
		'no_sslv2', 'no_sslv3', 'no_tlsv1', 'bugs', 'cipher=']
	optlist, optarg=getopt.getopt(args, '', options)

	cfg=Config()
	for opt in optlist:
		setattr(cfg, opt[0][2:], opt[1])
	for x in (('tlsv1','no_tlsv1'),('sslv3','no_sslv3'),('sslv2','no_sslv2')):
		if hasattr(cfg, x[0]) and hasattr(cfg, x[1]):
				raise ValueError, 'mutually exclusive: %s and %s' % x

	if hasattr(cfg, 'accept'):
		cfg.accept=string.split(cfg.connect, ':')
	else:
		cfg.accept=(HOST, PORT)

	cfg.protocol=[]
	# First protocol in the above list will be used.
	# Permutate the following tuple for preference. 
	for p in ('tlsv1', 'sslv3', 'sslv2'):
		if hasattr(cfg, p):
			cfg.protocol.append(p)
	cfg.protocol.append('sslv23')

	return cfg

RESP_HEAD="""\
HTTP/1.0 200 ok
Content-type: text/html

<HTML><BODY BGCOLOR=\"#ffffff\">
<pre>

Emulating s_server -www
Ciphers supported in s_server.py
"""

RESP_TAIL="""\
</pre>
</BODY></HTML>
"""

class channel(SSL.ssl_dispatcher):

	def __init__(self, conn):
		SSL.ssl_dispatcher.__init__(self, conn)
		#self.buffer=BIO.MemoryBuffer()
		self.buffer=cStringIO.StringIO()
		self.fixup_buffer()

	def fixup_buffer(self):
		even=0
		self.buffer.write(RESP_HEAD)
		for c in self.get_ciphers():
			# This formatting works for around 80 columns.
			self.buffer.write('%-11s:%-28s' % (c.version(), c.name()))
			if even:
				self.buffer.write('\r\n')
				even=1-even
		self.buffer.write('\r\n%s' % RESP_TAIL)
		self.buffer=self.buffer.getvalue()

	def handle_connect(self):
		pass

	def handle_close(self):
		self.close()

	def writeable(self):
		return len(self.buffer) > 0

	def handle_write(self):
		sent=self.send(self.buffer)
		self.buffer=self.buffer[sent:]


	def readable(self):
		return 1

	def handle_read(self):
		data=self.recv(1024)	# >/dev/null
		#print data


class server(SSL.ssl_dispatcher):

	channel_class=channel

	def __init__(self, addr, port, ssl_context):
		asyncore.dispatcher.__init__(self)
		self.create_socket(ssl_context)
		self.set_reuse_addr()
		self.socket.setblocking(0)
		self.bind((addr, port))
		self.listen(5)

	def handle_accept(self):
		sock, addr=self.accept()
		self.channel_class(sock)

	def writeable(self):
		return 0

def s_server(config):
	ctx=SSL.Context(config.protocol[0])
	ctx.load_cert('server.pem')
	server(cfg.accept[0], cfg.accept[1], ctx)
	asyncore.loop()

if __name__=='__main__':
	cfg=config(sys.argv[1:])
	s_server(cfg)

