#!/usr/bin/env python

"""A simple SSL 'echo' client.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echo.py,v 1.2 2000/08/23 15:47:42 ngps Exp $'

import getopt
import sys
from socket import gethostname
from M2Crypto import Err, Rand, SSL, X509, threading

host='127.0.0.1'
port=9999

optlist, optarg=getopt.getopt(sys.argv[1:], 'h:p:')
for opt in optlist:
    if '-h' in opt:
        host=opt[1]
    elif '-p' in opt:
        port=int(opt[1])

Rand.load_file('../randpool.dat', -1) 

ctx=SSL.Context('sslv3')
ctx.load_cert('client.pem')
ctx.load_verify_info('ca.pem')
ctx.load_client_ca('ca.pem')
ctx.set_verify(SSL.verify_none, 10)
ctx.set_info_callback()

s=SSL.Connection(ctx)
s.connect((host, port))
print 'Host =', gethostname()
print 'Cipher =', s.get_cipher().name()

v = s.get_verify_result()
if v != X509.V_OK:
    raise SystemExit, 'Server verification failed'

peer = s.get_peer_cert()
print 'Server =', peer.get_subject().CN

while 1:
    data = s.recv()
    if not data:
        print 'recv:',
        e = Err.get_error_code()
        #print Err.get_error_lib(e)
        #print Err.get_error_func(e)
        print Err.get_error_reason(e)
        break
    sys.stdout.write(data)
    sys.stdout.flush()
    buf=sys.stdin.readline()
    if not buf: 
        break
    n = s.send(buf)
    if not n:
        print 'send:', 
        e = Err.get_error_code()
        #print Err.get_error_lib(e)
        #print Err.get_error_func(e)
        print Err.get_error_reason(e)
        break

s.close()

Rand.save_file('../randpool.dat')

