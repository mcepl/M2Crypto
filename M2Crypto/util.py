#!/usr/bin/env python

""" Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: util.py,v 1.1 1999/08/19 15:44:17 ngps Exp $'

def h2b(s):
	import array
	ar=array.array('c')
	start=0
	if s[:2]=='0x':
		start=2
	for i in range(start, len(s), 2):
		num=eval("0x%s"%(s[i:i+2],))
		ar.append(chr(num))
	return ar.tostring()		

def pkcs5_pad(data, blklen=8):
	pad=(8-(len(data)%8))
	return data+chr(pad)*pad

def pkcs7_pad(data, blklen):
	if blklen>255:
		raise ValueError, 'illegal block size'
	pad=(blklen-(len(data)%blklen))
	return data+chr(pad)*pad

