"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: X509.py,v 1.1 1999/09/12 14:31:53 ngps Exp $'

import BIO
import M2Crypto 
m2=M2Crypto

m2.x509_init()

class X509:
	def __init__(self, x509):
		self.x509=x509

	def as_text(self):
		buf=BIO.MemoryBuffer()
		m2.x509_print(buf.bio_ptr(), self.x509)
		return buf.read_all()

class X509_Stack:
	def __init__(self, stack):
		self.stack=stack

	def __len__(self):
		return m2.sk_x509_num(self.stack)

	def __getitem__(self, idx):
		if idx < 0 or idx >= m2.sk_x509_num(self.stack):
			raise IndexError, 'index out of range'
		v=m2.sk_x509_value(self.stack, idx)
		return X509(v)


