""" M2Crypto wrapper for OpenSSL EVP API.
Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: EVP.py,v 1.2 1999/09/12 14:28:31 ngps Exp $'

from M2Crypto import md_ctx_new, md_ctx_free, \
	digest_init, digest_update, digest_final, \
	md5, sha1, ripemd160, \
	hmac_ctx_new, hmac_ctx_free, hmac_init, hmac_update, hmac_final, \
	cipher_ctx_new, cipher_ctx_free, \
	cipher_init, cipher_update, cipher_final, \
	bytes_to_key, rc4, \
	bf_ecb, bf_cbc, bf_cfb, bf_ofb,\
	idea_ecb, idea_cbc, idea_cfb, idea_ofb,\
	cast5_ecb, cast5_cbc, cast5_cfb, cast5_ofb,\
	rc5_ecb, rc5_cbc, rc5_cfb, rc5_ofb,\
	des_ecb, des_cbc, des_cfb, des_ofb,\
	des_ede_ecb, des_ede_cbc, des_ede_cfb, des_ede_ofb,\
	des_ede3_ecb, des_ede3_cbc, des_ede3_cfb, des_ede3_ofb,\
	pkey_new, pkey_free, sign_init, sign_update, sign_final

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
	
	digest=final

class HMAC:
	def __init__(self, algo, key):
		self.md=eval(algo)()
		if not self.md:
			raise ValueError, 'unknown algorithm'
		self.ctx=hmac_ctx_new()
		hmac_init(self.ctx, key, self.md)

	def __del__(self):
		if self.ctx:
			hmac_ctx_free(self.ctx)

	def update(self, data):
		hmac_update(self.ctx, data)

	def final(self):
		return hmac_final(self.ctx)
	
	digest=final

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

class PKey:
	def __init__(self, md, pkey=pkey_new()):
		self.pkey=pkey
		self.md=eval(md)()
		if not self.md:
			raise ValueError, 'unknown message digest'

	def __del__(self):
		if self.pkey:
			pkey_free(self.pkey)

	def update(self, data):
		sign_update(self.ctx, data)

	def final(self):
		return sign_final(self.ctx, self.pkey)

