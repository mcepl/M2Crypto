#!/usr/bin/env python

"""An M2Crypto implementation of OpenSSL's s_client.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: s_client.py,v 1.1 1999/09/12 09:25:30 ngps Exp $'

from socket import *
import getopt
import string
import sys

from M2Crypto import SSL

# s_server -www
HOST='127.0.0.1'
PORT=4433
REQ='GET / HTTP/1.0\r\n\r\n'

class Config:
	pass

def config(args):
	options=['connect=', 'verify=', 'cert=', 'key=', 'CApath=', 'CAfile=', \
		'reconnect', 'pause', 'showcerts', 'debug', 'nbio_test', 'state', \
		'nbio', 'crlf', 'sslv2', 'sslv3', 'tlsv1', 'no_sslv2', 'no_sslv3', \
		'no_tlsv1', 'bugs', 'cipher=']
	optlist, optarg=getopt.getopt(args, '', options)

	cfg=Config()
	for opt in optlist:
		setattr(cfg, opt[0][2:], opt[1])
	for x in (('tlsv1','no_tlsv1'),('sslv3','no_sslv3'),('sslv2','no_sslv2')):
		if hasattr(cfg, x[0]) and hasattr(cfg, x[1]):
				raise ValueError, 'mutually exclusive: %s and %s' % x

	if hasattr(cfg, 'connect'):
		cfg.connect=string.split(cfg.connect, ':')
	else:
		cfg.connect=(HOST, PORT)

	cfg.protocol=[]
	# First protocol in the above list will be used.
	# Permutate the following tuple for preference. 
	for p in ('tlsv1', 'sslv3', 'sslv2'):
		if hasattr(cfg, p):
			cfg.protocol.append(p)
	cfg.protocol.append('sslv23')

	return cfg

def s_client(config):
	ctx=SSL.Context(config.protocol[0])
	# SSL/CTX option-processing go here.
	ctx.load_cert('client.pem')
	#s=SSL.Socket(ctx)
	s=SSL.Connection(ctx)
	s.connect(cfg.connect)
	peer=s.get_peer_cert()
	if peer is not None:
		print(peer.as_text())
	s.send(REQ)
	while 1:
		data=s.recv(1024)
		if not data:
			break
		print data
	s.close()

if __name__=='__main__':
	cfg=config(sys.argv[1:])
	s_client(cfg)

