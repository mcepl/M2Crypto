""" M2Crypto wrapper for OpenSSL EVP API.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: EVP.py,v 1.3 2000/02/01 15:02:57 ngps Exp $'

import M2Crypto
m2 = M2Crypto

class MessageDigest:
    def __init__(self, algo):
        md = getattr(m2, algo)
        if not md:
            raise ValueError, 'unknown algorithm'
        self.md=md()
        self.ctx=m2.md_ctx_new()
        m2.digest_init(self.ctx, self.md)

    def __del__(self):
        if self.ctx:
            m2.md_ctx_free(self.ctx)

    def update(self, data):
        m2.digest_update(self.ctx, data)

    def final(self):
        return m2.digest_final(self.ctx)
    
    digest=final

class HMAC:
    def __init__(self, algo, key):
        md = getattr(m2, algo)
        if not md:
            raise ValueError, 'unknown algorithm'
        self.md=md()
        self.ctx=m2.hmac_ctx_new()
        m2.hmac_init(self.ctx, key, self.md)

    def __del__(self):
        if self.ctx:
            m2.hmac_ctx_free(self.ctx)

    def update(self, data):
        m2.hmac_update(self.ctx, data)

    def final(self):
        return m2.hmac_final(self.ctx)
    
    digest=final

class Cipher:
    def __init__(self, alg, key, iv, op, key_as_bytes=0, d='md5', salt='', i=1):
        cipher = getattr(m2, alg)
        if not cipher:
            raise ValueError, 'unknown cipher'
        self.cipher=cipher()
        if key_as_bytes:
            kmd = getattr(m2, d)
            if not kmd:
                raise ValueError, 'unknown message digest'
            key = m2.bytes_to_key(self.cipher, kmd(), key, salt, iv, i)
        self.ctx=m2.cipher_ctx_new()
        m2.cipher_init(self.ctx, self.cipher, key, iv, op)
        del key

    def __del__(self):
        if self.ctx:
            m2.cipher_ctx_free(self.ctx)

    def update(self, data):
        return m2.cipher_update(self.ctx, data)

    def final(self):
        return m2.cipher_final(self.ctx)

class PKey:
    def __init__(self, md, pkey=m2.pkey_new()):
        self.pkey=pkey
        md = getattr(m2, md)
        if not md:
            raise ValueError, 'unknown message digest'
        self.md = md()

    def __del__(self):
        if self.pkey:
            m2.pkey_free(self.pkey)

    def update(self, data):
        m2.sign_update(self.ctx, data)

    def final(self):
        return m2.sign_final(self.ctx, self.pkey)

