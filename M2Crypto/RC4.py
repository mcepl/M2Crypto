#!/usr/bin/env python

RCS_id='$Id: RC4.py,v 1.1 1999/08/16 15:32:16 ngps Exp $'

from M2Crypto import rc4_new, rc4_free, \
	rc4_set_key, rc4_update

class RC4:
	def __init__(self, key=None):
		self.cipher=rc4_new()
		if key:
			rc4_set_key(self.cipher, key)

	def __del__(self):
		rc4_free(self.cipher)

	def set_key(self, key):
		if key:
			rc4_set_key(self.cipher, key)	
		else:
			raise ValueError, 'key==None'

	def update(self, data):
		return rc4_update(self.cipher, data)

	def final(self):
		return ''


