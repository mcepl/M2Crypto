#!/usr/bin/env python

"""DSA demonstration.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: dsatest.py,v 1.1 1999/09/12 14:44:20 ngps Exp $'

from M2Crypto import DSA, EVP

md=EVP.MessageDigest('sha1')
md.update('can you spell subliminal channel?')
dgst=md.digest()

d=DSA.load_key('dsatest.pem')

def test():
	print 'testing signing...',
	r,s=d.sign(dgst)
	if not d.verify(dgst, r, s):
		print 'not ok'
	else:
		print 'ok'

def test_asn1():
	# XXX Randomly fails: bug in there somewhere
	print 'testing asn1 signing...',
	blob=d.sign_asn1(dgst)
	if not d.verify_asn1(dgst, blob):
		print 'not ok'
	else:
		print 'ok'

if __name__=='__main__':
	test()
	test_asn1()

