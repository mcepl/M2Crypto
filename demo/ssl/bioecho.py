#!/usr/bin/env python

"""A simple SSL 'echo' client that uses the BIO interface.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: bioecho.py,v 1.1 2000/04/17 15:53:30 ngps Exp $'

import getopt
import sys
from M2Crypto import Err, SSL, X509

host='127.0.0.1'
port=9999

optlist, optarg=getopt.getopt(sys.argv[1:], 'h:p:')
for opt in optlist:
    if '-h' in opt:
        host=opt[1]
    elif '-p' in opt:
        port=opt[1]

ctx=SSL.Context('sslv3')
ctx.load_cert('client0.pem')
ctx.load_verify_info('ca.pem')
#ctx.load_client_ca('ca.pem')
ctx.set_verify(SSL.verify_peer, 10)
#ctx.set_info_callback()

s=SSL.Connection(ctx)
s.connect((host, port))
print 'Cipher =', s.get_cipher().name()

v = s.get_verify_result()
if v != X509.V_OK:
    raise SystemExit, 'Server verification failed'

peer = s.get_peer_cert()
print 'Server =', peer.get_subject().CN

bio = s.makefile('rw')
#s.close()  # XXX currently this kills M2Crypto.

while 1:
    data = bio.readline()
    if not data:
        print 'readline:',
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
    n = bio.write(buf)
    bio.flush()
    if not n:
        print 'write:', 
        e = Err.get_error_code()
        #print Err.get_error_lib(e)
        #print Err.get_error_func(e)
        print Err.get_error_reason(e)
        break

bio.close()
s.close()

