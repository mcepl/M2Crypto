#!/usr/bin/env python

"""C programming in Python. Have Swig worry the pointers. ;-)

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: c.py,v 1.1 1999/09/12 09:24:15 ngps Exp $'

from socket import *
import sys

from M2Crypto import SSL
m2=SSL.m2

HOST='127.0.0.1'
PORT=443
req='GET / HTTP/1.0\r\n\r\n'

def c_style():
	ctx=m2.ssl_ctx_new(m2.sslv3_method())
	s=socket(AF_INET, SOCK_STREAM)
	s.connect((HOST, PORT))
	sbio=m2.bio_new_socket(s.fileno(), 0)
	ssl=m2.ssl_new(ctx)
	m2.ssl_set_bio(ssl, sbio, sbio)
	m2.ssl_connect(ssl)
	sslbio=m2.bio_new(m2.bio_f_ssl())
	m2.bio_set_ssl(sslbio, ssl, 0)
	m2.bio_write(sslbio, req)
	data=m2.bio_read(sslbio, 4096)
	print data
	m2.ssl_shutdown(ssl)
	m2.ssl_free(ssl)
	m2.ssl_ctx_free(ctx)
	s.close()

if __name__=='__main__':
	c_style()

