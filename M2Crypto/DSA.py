"""M2Crypto wrapper for OpenSSL DSA API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import sys
import util, BIO, m2

class DSAError(Exception): pass

m2.dsa_init(DSAError)

class DSA:

    """
    Object interface to a DSA key pair.
    """

    def __init__(self, dsa, _pyfree=0):
        assert m2.dsa_type_check(dsa), "'dsa' type error"
        self.dsa = dsa
        self._pyfree = _pyfree

    def __del__(self):
        try:
            if self._pyfree:
                m2.dsa_free(self.dsa)
        except AttributeError:
            pass

    def __len__(self):
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        return m2.dsa_keylen(self.dsa)

    def __getattr__(self, name):
        if name in ['p', 'q', 'g', 'pub', 'priv']:
            method = getattr(m2, 'dsa_get_%s' % (name,))
            assert m2.dsa_type_check(self.dsa), "'dsa' type error"
            return method(self.dsa)
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if name in ['p', 'q', 'g']:
            raise DSAError, 'set (p, q, g) via set_params()'
        elif name in ['pub','priv']:
            raise DSAError, 'generate (pub, priv) via gen_key()'
        else:
            self.__dict__[name] = value

    def set_params(self, p, q, g):
        m2.dsa_set_p(self.dsa, p)
        m2.dsa_set_q(self.dsa, q)
        m2.dsa_set_g(self.dsa, g)

    def gen_key(self):
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        m2.dsa_gen_key(self.dsa)   

    def save_key(self, file, callback=util.passphrase_callback):
        pass

    def save_params(self, file):
        pass

    def sign(self, digest):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_sign(self.dsa, digest)
    
    def verify(self, digest, r, s):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_verify(self.dsa, digest, r, s)

    def sign_asn1(self, digest):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_sign_asn1(self.dsa, digest)
    
    def verify_asn1(self, digest, blob):
        assert self.check_key(), 'key is not initialised'
        return m2.dsa_verify_asn1(self.dsa, digest, blob)

    def check_key(self):
        assert m2.dsa_type_check(self.dsa), "'dsa' type error"
        return m2.dsa_check_key(self.dsa)
        


class DSA_pub(DSA):

    """
    Object interface to a DSA public key.
    """

    def __init__(self, *args):
        raise NotImplementedError


def paramgen_callback(p, n, out=sys.stdout):
    """
    Default callback for gen_params().
    """
    ch = ['.','+','*','\n']
    out.write(ch[p])
    out.flush()


def gen_params(bits, callback=paramgen_callback):
    """
    Factory function that generates DSA parameters and 
    instantiates a DSA object from the output.

    'bits' is the length of the prime to be generated. If 
    'bits' < 512, it is set to 512.

    'callback' is a Python callback object that will be 
    invoked during parameter generation; it usual purpose 
    is to provide visual feedback.
    """
    return DSA(m2.dsa_generate_parameters(bits, callback), 1)


def load_params(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object with DSA 
    parameters.

    'file' names the file that contains the PEM representation 
    of the DSA parameters.

    'callback' is a Python callback object that will be 
    invoked if the DSA parameters file is passphrase-protected.
    """
    bio = BIO.openfile(file)
    return load_params_bio(bio, callback)


def load_params_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object with DSA
    parameters.

    'bio' is a M2Crypto.BIO object that contains the PEM 
    representation of the DSA parameters.

    'callback' is a Python callback object that will be 
    invoked if the DSA parameters are passphrase-protected.
    """
    return DSA(m2.dsa_read_params(bio._ptr(), callback), 1)


def load_key(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object.

    'file' names the file that contains the PEM representation 
    of the DSA key pair.

    'callback' is a Python callback object that will be invoked 
    if the DSA key pair is passphrase-protected.
    """
    bio = BIO.openfile(file)
    return load_key_bio(bio, callback)


def load_key_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates a DSA object.

    'bio' is an M2Crypto.BIO object that contains the PEM
    representation of the DSA key pair. 

    'callback' is a Python callback object that will be invoked 
    if the DSA key pair is passphrase-protected.
    """
    return DSA(m2.dsa_read_key(bio._ptr(), callback), 1)

