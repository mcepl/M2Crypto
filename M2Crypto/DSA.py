"""M2Crypto wrapper for OpenSSL DSA API.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: DSA.py,v 1.3 2000/02/01 15:05:38 ngps Exp $'

import util
import BIO
import M2Crypto
m2=M2Crypto

m2.dsa_init()

class DSA:
	def __init__(self, this):
		self.this=this

	def __del__(self):
		m2.dsa_free(self.this)

	def __len__(self):
		return m2.dsa_size(self.this)

	def __getattr__(self, name):
		if name in ['p', 'q', 'g', 'pub', 'priv']:
			method=getattr(m2, 'm2.dsa_get_%s' % (name,))
			return method(self.this)
		else:
			raise AttributeError

	def __setattr__(self, name, value):
		if name in ['p', 'q', 'g']:
			raise AttributeError, 'set (p, q, g) via set_params()'
		elif name in ['pub','priv']:
			raise AttributeError, 'generate (pub, priv) via gen_key()'
		else:
			self.__dict__[name]=value

	def set_params(self, p, q, g):
		m2.dsa_set_p(self.this, p)
		m2.dsa_set_q(self.this, q)
		m2.dsa_set_g(self.this, g)

	def gen_key(self):
		m2.dsa_gen_key(self.this)	

	def save_key(self, file, callback=util.passphrase_callback):
		pass

	def save_params(self, file):
		pass

	def sign(self, digest):
		return m2.dsa_sign(self.this, digest)
	
	def verify(self, digest, r, s):
		return m2.dsa_verify(self.this, digest, r, s)

	def sign_asn1(self, digest):
		return m2.dsa_sign_asn1(self.this, digest)
	
	def verify_asn1(self, digest, blob):
		return m2.dsa_verify_asn1(self.this, digest, blob)

class DSA_pub(DSA):
	pass	

def gen_params(plen, seed, counter, h, g, callback=util.genparam_callback):
	pass

def load_params(file, callback=util.passphrase_callback):
	f=open(file)
	dsa=dsa_read_params(f, callback)
	f.close()
	return DSA(dsa)

def load_key(file, callback=util.passphrase_callback):
	f=BIO.openfile(file)
	dsa=m2.dsa_read_key(f.bio_ptr(), callback)
	f.close()
	return DSA(dsa)

def load_key0(file, callback=util.passphrase_callback):
	f=open(file)
	dsa=m2.dsa_read_key(f, callback)
	f.close()
	return DSA(dsa)


