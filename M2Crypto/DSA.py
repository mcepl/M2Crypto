#!/usr/bin/env python

RCS_id='$Id: DSA.py,v 1.1 1999/08/16 15:31:39 ngps Exp $'

from M2Crypto import dsa_init, dsa_new, dsa_free, dsa_size, \
	dsa_get_p, dsa_get_q, dsa_get_g, dsa_get_pub, dsa_get_priv, \
	dsa_set_p, dsa_set_q, dsa_set_g, \
	dsa_gen_key, dsa_sign, dsa_verify, \
	dsa_read_params, dsa_read_key

dsa_init()

def passphrase_callback(v):
	from getpass import getpass
	while 1:
		p1=getpass('Enter passphrase: ')
		if v:
			p2=getpass('Verify passphrase: ')
			if p1==p2:
				break
		else:
			break
	return p1

class DSA:
	def __init__(self, this=dsa_new()):
		self.this=this

	def __del__(self):
		dsa_free(self.this)

	def __len__(self):
		return dsa_size(self.this)

	def __getattr__(self, name):
		if name in ['p', 'q', 'g', 'pub', 'priv']:
			method=eval('dsa_get_%s' % (name,))
			return long(method(self.this))
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
		dsa_set_p(self.this, str(p))
		dsa_set_q(self.this, str(q))
		dsa_set_g(self.this, str(g))

	def gen_key(self):
		dsa_gen_key(self.this)	

	def save_key(self, file, callback=passphrase_callback):
		pass

	def save_params(self, file):
		pass

	def sign(self, digest):
		return dsa_sign(self.this, digest)
	
	def verify(self, digest, r, s):
		return dsa_verify(self.this, digest, str(r), str(s))

class DSA_pub(DSA):
	pass	

def genparam_callback(p, n):
	from sys import stdout
	ch=['.','+','*','\n']
	stdout.write(ch[p])
	stdout.flush()

def gen_params(plen, seed, counter, h, g, callback=genparam_callback):
	pass

def load_params(file, callback=passphrase_callback):
	f=open(file)
	dsa=dsa_read_params(f, callback)
	f.close()
	return DSA(dsa)

def load_key(file, callback=passphrase_callback):
	f=open(file)
	dsa=dsa_read_key(f, callback)
	f.close()
	return DSA(dsa)

if __name__=='__main__':
	pass
