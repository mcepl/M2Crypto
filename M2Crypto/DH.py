"""M2Crypto wrapper for OpenSSL DH API.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: DH.py,v 1.3 2000/02/25 15:28:00 ngps Exp $'

from util import genparam_callback
import BIO
import Err
import M2Crypto
m2=M2Crypto

m2.dh_init()

class DH:
    def __init__(self, this=None, _pyfree=0):
        if this is not None:
            self.this = this
            self._pyfree = _pyfree
        else:
            self.this = m2.dh_new()
            self._pyfree = 1

    def __del__(self):
        if self._pyfree:
            m2.dh_free(self.this)

    def __len__(self):
        return m2.dh_size(self.this)

    def __getattr__(self, name):
        if name=='p':
            return m2.dh_get_p(self.this)
        elif name=='g':
            return m2.dh_get_g(self.this)
        elif name=='pub':
            return m2.dh_get_pub(self.this)
        elif name=='priv':
            return m2.dh_get_priv(self.this)
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
        m2.dh_set_p(self.this, p)
        m2.dh_set_g(self.this, g)

    def check_params(self):
        return m2.dh_check(self.this)
        
    def gen_key(self):
        m2.dh_generate_key(self.this)   

    def compute_key(self, pubkey):
        return m2.dh_compute_key(self.this, pubkey)

def gen_params(plen, g, callback=genparam_callback):
    return DH(m2.dh_generate_parameters(plen, g, callback), 1)

def load_params(file):
    f=BIO.openfile(file)
    cptr=m2.dh_read_parameters(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return DH(cptr, 1)

def free_params(cptr):
    m2.dh_free(cptr)


