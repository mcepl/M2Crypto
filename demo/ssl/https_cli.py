#!/usr/bin/env python

"""Demonstrations of M2Crypto.urllib2 and M2Crypto.httpslib.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: https_cli.py,v 1.1 1999/09/12 09:25:23 ngps Exp $'

import sys
from M2Crypto import SSL, httpslib, urllib2

def test_httpslib():
	ctx=SSL.Context('sslv3')
	h=httpslib.HTTPS(ctx, '127.0.0.1')
	h.putrequest('GET', '/')
	h.putheader('Accept', 'text/html')
	h.putheader('Accept', 'text/plain')
	h.endheaders()
	errcode, errmsg, headers=h.getreply()
	f=h.getfile()
	while 1:
		data=f.readline()	
		if not data:
			break
		sys.stdout.write(data)
	f.close()

def test_urllib2():
	url=urllib2.urlopen('https://127.0.0.1')
	data=url.readlines()
	for d in data:
		sys.stdout.write(d)

if __name__=='__main__':
	#test_httpslib()
	test_urllib2()

