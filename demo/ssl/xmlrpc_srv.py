"""Server demonstration of M2Crypto.xmlrpclib2.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: xmlrpc_srv.py,v 1.1 2000/04/17 16:01:05 ngps Exp $'

# M2Crypto
from M2Crypto import DH, SSL
from echod_lib import init_context

# /F's xmlrpcserver.py.
from xmlrpcserver import RequestHandler

class xmlrpc_handler(RequestHandler):
    def call(self, method, params):
        print "XMLRPC call:", method, params
        return params

if __name__ == '__main__':
    ctx = init_context('sslv23', 'server.pem', 'ca.pem', SSL.verify_none)
    ctx.set_tmp_dh('dh1024.pem')
    s = SSL.ThreadingSSLServer(('', 9443), RequestHandler, ctx)
    s.serve_forever()   

