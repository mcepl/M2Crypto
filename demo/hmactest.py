#!/usr/bin/env python

"""HMAC demonstration.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: hmactest.py,v 1.1 1999/09/12 14:44:50 ngps Exp $'

from M2Crypto import EVP
from M2Crypto.util import h2b

data1=['', 'More text test vectors to stuff up EBCDIC machines :-)', \
	h2b("e9139d1e6ee064ef8cf514fc7dc83e86")]

data2=[h2b('0b'*16), "Hi There", \
	h2b("9294727a3638bb1c13f48ef8158bfc9d")]

data3=['Jefe', "what do ya want for nothing?", \
	h2b("750c783e6ab0b503eaa86e310a5db738")]

data4=[h2b('aa'*16), h2b('dd'*50), \
	h2b("56be34521d144c88dbb8c733f0e8b3f6")]

data=[data1, data2, data3, data4]

def test():
	print 'testing hmac'
	algo='md5'
	for d in data:
		h=EVP.HMAC(algo, d[0])
		h.update(d[1])
		ret=h.final()
		if ret!=d[2]:
			print data.index(d)+1, 'not ok'	
		else:
			print 'ok'

if __name__=='__main__':
	test()

