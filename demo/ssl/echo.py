#!/usr/bin/env python

"""A simple SSL 'echo' client.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echo.py,v 1.1 1999/09/12 09:24:25 ngps Exp $'

import getopt
import sys
from M2Crypto import SSL

host='127.0.0.1'
port=9999

optlist, optarg=getopt.getopt(sys.argv[1:], 'h:p:')
for opt in optlist:
	if '-h' in opt:
		host=opt[1]
	elif '-p' in opt:
		port=opt[1]

ctx=SSL.Context('tlsv1')
s=SSL.Connection(ctx)
s.connect((host, port))
print 'Cipher =', s.get_cipher().name()
print

data=s.recv()
print data
while 1:
	buf=sys.stdin.readline()
	if not buf: 
		break
	s.send(buf)
	data=s.recv()
	sys.stdout.write(data)
	sys.stdout.flush()
s.close()

