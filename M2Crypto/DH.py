#!/usr/bin/env python

RCS_id='$Id: DH.py,v 1.1 1999/08/16 15:31:29 ngps Exp $'

from _m2crypto import dh_init, dh_new, dh_free, dh_generate_parameters, \
	dh_size, dh_get_g, dh_get_p, dh_get_pub, dh_get_priv, \
	dh_set_p, dh_set_g, dh_check, dh_generate_key, dh_compute_key
dh_init()

class DH:
	def __init__(self, this=dh_new()):
		self.this=this

	def __del__(self):
		dh_free(self.this)

	def __len__(self):
		return dh_size(self.this)

	def __getattr__(self, name):
		if name=='g':
			return int(dh_get_g(self.this))
		elif name=='p':
			return long(dh_get_p(self.this))
		elif name=='pub':
			return long(dh_get_pub(self.this))
		elif name=='priv':
			return long(dh_get_priv(self.this))
		else:
			raise AttributeError

	def __setattr__(self, name, value):
		if name in ['p', 'g']:
			raise AttributeError, 'set (p, g) via set_params()'
		elif name in ['pub','priv']:
			raise AttributeError, 'generate (pub, priv) via gen_key()'
		else:
			self.__dict__[name]=value

	def set_params(self, p, g):
		dh_set_p(self.this, str(p))	
		dh_set_g(self.this, str(g))	

	def check_params(self):
		return dh_check(self.this)
		
	def gen_key(self):
		dh_generate_key(self.this)	

	def compute_key(self, pubkey):
		# XXX pubkey should be PyLong or BIGNUM, not PyString
		return dh_compute_key(self.this, str(pubkey)[:-1])

def genparam_callback(p, n):
	from sys import stdout
	ch=['.','+','*','\n']
	stdout.write(ch[p])
	stdout.flush()

def gen_params(plen, g, callback=genparam_callback):
	return DH(this=dh_generate_parameters(plen, g, callback))

def load_params(file):
	f=open(file)
	dh=dh_read_params(f, callback)
	f.close()
	return DH(dh)

