#!/usr/bin/env python

RCS_id='$Id: RSA.py,v 1.1 1999/08/16 15:32:38 ngps Exp $'

from _rsa import *
lib_init()
rsa_init()

class RSA:
	def __init__(self, this=rsa_new()):
		self.this=this

	def __del__(self):
		rsa_free(self.this)

	def __len__(self):
		return rsa_size(self.this)

	def __getattr__(self, name):
		if name=='e':
			return int(rsa_get_e(self.this))
		elif name=='n':
			return long(rsa_get_n(self.this))
		else:
			raise AttributeError

	def pub(self):
		return rsa_get_e(self.this), rsa_get_n(self.this)

	def public_encrypt(self, data, padding):
		return rsa_public_encrypt(self.this, data, padding)

	def public_decrypt(self, data, padding):
		return rsa_public_decrypt(self.this, data, padding)

	def private_encrypt(self, data, padding):
		return rsa_private_encrypt(self.this, data, padding)

	def private_decrypt(self, data, padding):
		return rsa_private_decrypt(self.this, data, padding)

	def save_pub_key(self, file):
		return rsa_write_pub_key(self.this, file)

class RSA_pub(RSA):
	def __setattr__(self, name, value):
		if name=='e':
			return rsa_set_e(self.this, value)
		elif name=='n':
			return rsa_set_n(self.this, value)
		else:
			self.__dict__[name]=value
		
	def private_encrypt(self, *argv):
		raise 'private key not available'

	def private_decrypt(self, *argv):
		raise 'private key not available'

	def save_key(self, file):
		rsa_write_pub_key(self.this, file)

def new_pub_key(e, n):
	r=RSA_pub()
	r.e=str(e)
	r.n=str(n)[:-1]
	return r

def load_pub_key(file):
	f=open(file)
	r=rsa_read_pub_key(f)
	f.close()
	return RSA_pub(r)

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
			
def load_key(file, callback=passphrase_callback):
	f=open(file)
	r=rsa_read_key(f, callback)
	f.close()
	return RSA(r)

if __name__=='__main__':
	r=load_pem('fred.pem')
	print r.e
	print r.n

