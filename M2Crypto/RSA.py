"""M2Crypto wrapper for OpenSSL RSA API.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: RSA.py,v 1.4 2000/02/25 15:27:21 ngps Exp $'

import util
import BIO
import Err
import M2Crypto
m2=M2Crypto

m2.rsa_init()

no_padding=m2.no_padding
pkcs1_padding=m2.pkcs1_padding
sslv23_padding=m2.sslv23_padding
pkcs1_oaep_padding=m2.pkcs1_oaep_padding


class RSA:
    def __init__(self, this=None, _pyfree=0):
        if this is not None:
            self.this = this
            self._pyfree = _pyfree
        else:
            self.this = m2.rsa_new()
            self._pyfree = 1

    def __del__(self):
        if self._pyfree:
            m2.rsa_free(self.this)

    def __len__(self):
        return m2.rsa_size(self.this)

    def __getattr__(self, name):
        if name=='e':
            return m2.rsa_get_e(self.this)
        elif name=='n':
            return m2.rsa_get_n(self.this)
        else:
            raise AttributeError

    def pub(self):
        return m2.rsa_get_e(self.this), m2.rsa_get_n(self.this)

    def public_encrypt(self, data, padding):
        return m2.rsa_public_encrypt(self.this, data, padding)

    def public_decrypt(self, data, padding):
        return m2.rsa_public_decrypt(self.this, data, padding)

    def private_encrypt(self, data, padding):
        return m2.rsa_private_encrypt(self.this, data, padding)

    def private_decrypt(self, data, padding):
        return m2.rsa_private_decrypt(self.this, data, padding)

    def save_pub_key(self, file):
        return m2.rsa_write_pub_key(self.this, file)


class RSA_pub(RSA):
    def __setattr__(self, name, value):
        # XXX Raise exception if e or n are not in order.
        if name=='e':
            return m2.rsa_set_e(self.this, value)
        elif name=='n':
            return m2.rsa_set_n(self.this, value)
        else:
            self.__dict__[name]=value
        
    def private_encrypt(self, *argv):
        raise 'private key not available'

    def private_decrypt(self, *argv):
        raise 'private key not available'

    def save_key(self, file):
        m2.rsa_write_pub_key(self.this, file)

def new_pub_key(e, n):
    r = RSA_pub()
    r.e = e
    r.n = n
    # XXX Sanity-checking of (e, n)
    return r

def load_pub_key(file):
    f=BIO.openfile(file)
    cptr=m2.rsa_read_pub_key(f.bio)
    f.close()
    return RSA_pub(cptr, 1)

def load_pub_key0(file):
    f=open(file)
    cptr=m2.rsa_read_pub_key(f)
    f.close()
    return RSA_pub(cptr, 1)

def load_key(file, callback=util.passphrase_callback):
    f=BIO.openfile(file)
    cptr=m2.rsa_read_key(f.bio_ptr(), callback)
    f.close()
    if cptr is None:
        raise Err.get_error()
    return RSA(cptr, 1)

def load_key0(file, callback=util.passphrase_callback):
    f=open(file)
    cptr=m2.rsa_read_key(f, callback)
    f.close()
    return RSA(cptr, 1)

