"""M2Crypto wrapper for OpenSSL EVP API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: EVP.py,v 1.9 2003/10/26 13:16:52 ngps Exp $'

import Err, util
import m2

class MessageDigest:
    def __init__(self, algo):
        md = getattr(m2, algo)
        if not md:
            raise ValueError, ('unknown algorithm', algo)
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
    def __init__(self, key, algo='sha1'):
        md = getattr(m2, algo)
        if not md:
            raise ValueError, ('unknown algorithm', algo)
        self.md=md()
        self.ctx=m2.hmac_ctx_new()
        m2.hmac_init(self.ctx, key, self.md)

    def __del__(self):
        if self.ctx:
            m2.hmac_ctx_free(self.ctx)

    def reset(self, key):
        m2.hmac_init(self.ctx, key, self.md)

    def update(self, data):
        m2.hmac_update(self.ctx, data)

    def final(self):
        return m2.hmac_final(self.ctx)
    
    digest=final

def hmac(key, data, algo='sha1'):
    md = getattr(m2, algo)
    if not md:
        raise ValueError, ('unknown algorithm', algo)
    return m2.hmac(key, data, md())


class Cipher:
    def __init__(self, alg, key, iv, op, key_as_bytes=0, d='md5', salt='12345678', i=1):
        cipher = getattr(m2, alg)
        if not cipher:
            raise ValueError, ('unknown cipher', alg)
        self.cipher=cipher()
        if key_as_bytes:
            kmd = getattr(m2, d)
            if not kmd:
                raise ValueError, ('unknown message digest', d)
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
    def __init__(self, pkey=None, _pyfree=0, md='sha1'):
        if pkey is not None:
            self.pkey = pkey
            self._pyfree = _pyfree
        else:
            self.pkey = m2.pkey_new()
            self._pyfree = 1
        mda = getattr(m2, md)
        if not mda:
            raise ValueError, ('unknown message digest', md)
        self.md = mda()

    def __del__(self):
        if self._pyfree:
            m2.pkey_free(self.pkey)

    def _ptr(self):
        return self.pkey

    def update(self, data):
        m2.sign_update(self.ctx, data)

    def final(self):
        return m2.sign_final(self.ctx, self.pkey)

    def assign_rsa(self, rsa):
        ret = m2.pkey_assign_rsa(self.pkey, rsa.rsa)
        if ret:
            rsa._pyfree = 0
        return ret

def load_key(file, callback=util.passphrase_callback):
    bio = m2.bio_new_file(file, 'r')
    if bio is None:
        raise Err.get_error()
    cptr = m2.pkey_read_pem(bio, callback)
    m2.bio_free(bio)
    if cptr is None:
        raise Err.get_error()
    return PKey(cptr, 1)

def load_key_bio(bio, callback=util.passphrase_callback):
    cptr = m2.pkey_read_pem(bio._ptr(), callback)
    if cptr is None:
        raise Err.get_error()
    return PKey(cptr, 1)
