#!/usr/bin/env python

RCS_id='$Id: EVP.py,v 1.1 1999/08/16 15:31:48 ngps Exp $'

from M2Crypto import md_ctx_new, md_ctx_free, \
	digest_init, digest_update, digest_final, \
	md5, sha1, ripemd160, \
	cipher_ctx_new, cipher_ctx_free, \
	cipher_init, cipher_update, cipher_final, \
	bytes_to_key, \
	bf_ecb, bf_cbc, bf_cfb, bf_ofb,\
	idea_ecb, idea_cbc, idea_cfb, idea_ofb,\
	cast5_ecb, cast5_cbc, cast5_cfb, cast5_ofb,\
	rc5_ecb, rc5_cbc, rc5_cfb, rc5_ofb,\
	des_ecb, des_cbc, des_cfb, des_ofb,\
	des_ede_ecb, des_ede_cbc, des_ede_cfb, des_ede_ofb,\
	des_ede3_ecb, des_ede3_cbc, des_ede3_cfb, des_ede3_ofb,\
	rc4

class MessageDigest:
	def __init__(self, algo):
		self.md=eval(algo)()
		if not self.md:
			raise ValueError, 'unknown algorithm'
		self.ctx=md_ctx_new()
		digest_init(self.ctx, self.md)

	def __del__(self):
		if self.ctx:
			md_ctx_free(self.ctx)

	def update(self, data):
		digest_update(self.ctx, data)

	def final(self):
		return digest_final(self.ctx)

class Cipher:
	def __init__(self, alg, key, iv, op, key_as_bytes=0, d='md5', salt='', i=1):
		self.cipher=eval(alg)()
		if not self.cipher:
			raise ValueError, 'unknown cipher'
		if key_as_bytes:
			kmd=eval(d)()
			if not kmd:
				raise ValueError, 'unknown message digest'
			key=bytes_to_key(self.cipher, kmd, key, salt, iv, i)
		self.ctx=cipher_ctx_new()
		cipher_init(self.ctx, self.cipher, key, iv, op)
		del key

	def __del__(self):
		if self.ctx:
			cipher_ctx_free(self.ctx)

	def update(self, data):
		return cipher_update(self.ctx, data)

	def final(self):
		return cipher_final(self.ctx)

