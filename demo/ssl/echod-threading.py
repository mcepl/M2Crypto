#!/usr/bin/env python

"""A multi-threading SSL 'echo' server.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: echod-threading.py,v 1.2 1999/10/01 16:12:25 ngps Exp $'

from M2Crypto import SSL, threading
import echod_lib

class ssl_echo_handler(echod_lib.ssl_echo_handler):
    buffer='Ye Olde Threading Echo Servre\r\n'


if __name__=='__main__':
    try:
	    threading.init()
	    ctx=echod_lib.init_context('sslv23', 'server.pem', 'ca.pem', SSL.verify_peer)
	    s=SSL.ThreadingSSLServer(('', 9999), ssl_echo_handler, ctx)
	    s.serve_forever()   
    except:
        threading.cleanup()
        pass

