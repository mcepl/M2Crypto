"""M2Crypto wrapper for OpenSSL RSA API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: RSA.py,v 1.6 2002/12/23 03:49:03 ngps Exp $'

import sys
import util, BIO, Err, m2

class RSAError(Exception): pass

m2.rsa_init(RSAError)

no_padding = m2.no_padding
pkcs1_padding = m2.pkcs1_padding
sslv23_padding = m2.sslv23_padding
pkcs1_oaep_padding = m2.pkcs1_oaep_padding


class RSA:

    """
    Object interface to an RSA key pair.
    """

    def __init__(self, rsa, _pyfree=0):
        assert m2.rsa_type_check(rsa), "'rsa' type error"
        self.rsa = rsa
        self._pyfree = _pyfree

    def __del__(self):
        try:
            if self._pyfree:
                m2.rsa_free(self.rsa)
        except AttributeError:
            pass

    def __len__(self):
        return m2.rsa_size(self.rsa) << 3

    def __getattr__(self, name):
        if name == 'e':
            return m2.rsa_get_e(self.rsa)
        elif name == 'n':
            return m2.rsa_get_n(self.rsa)
        else:
            raise AttributeError

    def pub(self):
        assert self.check_key(), 'key is not initialised'
        return m2.rsa_get_e(self.rsa), m2.rsa_get_n(self.rsa)

    def public_encrypt(self, data, padding):
        assert self.check_key(), 'key is not initialised'
        return m2.rsa_public_encrypt(self.rsa, data, padding)

    def public_decrypt(self, data, padding):
        assert self.check_key(), 'key is not initialised'
        return m2.rsa_public_decrypt(self.rsa, data, padding)

    def private_encrypt(self, data, padding):
        assert self.check_key(), 'key is not initialised'
        return m2.rsa_private_encrypt(self.rsa, data, padding)

    def private_decrypt(self, data, padding):
        assert self.check_key(), 'key is not initialised'
        return m2.rsa_private_decrypt(self.rsa, data, padding)

    def save_key_bio(self, bio, cipher='des_ede3_cbc', callback=util.passphrase_callback):
        """
        Save the key pair to an M2Crypto.BIO object in PEM format.

        _bio_ is the target M2Crypto.BIO object.

        _cipher_ is a symmetric cipher to protect the key. The 
        default cipher is 'des_ede3_cbc', i.e., three-key triple-DES
        in cipher block chaining mode.

        _callback_ is a Python callable object that is invoked
        to acquire a passphrase with which to protect the key.
        """
        if cipher is None:
            ciph = None
        else:
            ciph = getattr(m2, cipher, None)
            if ciph is None:
                raise RSAError, 'not such cipher %s' % cipher 
            else:
                ciph = ciph()
        return m2.rsa_write_key(self.rsa, bio._ptr(), ciph, callback)

    def save_key(self, file, cipher='des_ede3_cbc', callback=util.passphrase_callback):
        """
        Save the key pair to filename _file_ in PEM format.
        """
        bio = BIO.openfile(file, 'wb')
        return self.save_key_bio(bio, cipher, callback)

    def save_key_der_bio(self, bio):
        """
        Save the key pair to the M2Crypto.BIO object 'bio' in DER format.
        """
        return m2.rsa_write_key_der(self.rsa, bio._ptr())

    def save_key_der(self, file):
        """
        Save the key pair to 'file' in DER format.
        """
        bio = BIO.openfile(file, 'wb')
        return self.save_key_der_bio(bio)

    def save_pub_key_bio(self, bio):
        """
        Save the public key to the M2Crypto.BIO object 'bio' in PEM format.
        """ 
        return m2.rsa_write_pub_key(self.rsa, bio._ptr())

    def save_pub_key(self, file):
        """
        Save the public key to filename 'file' in PEM format.
        """
        bio = BIO.openfile(file, 'wb')
        return m2.rsa_write_pub_key(self.rsa, bio._ptr())

    def check_key(self):
        return m2.rsa_check_key(self.rsa)


class RSA_pub(RSA):

    """
    Object interface to an RSA public key.
    """

    def __setattr__(self, name, value):
        if name in ['e', 'n']:
            raise RSAError, \
                'use factory function new_pub_key() to set (e, n)'
        else:
            self.__dict__[name] = value
        
    def private_encrypt(self, *argv):
        raise RSAError, 'RSA_pub object has no private key'

    def private_decrypt(self, *argv):
        raise RSAError, 'RSA_pub object has no private key'

    save_key = RSA.save_pub_key

    save_key_bio = RSA.save_pub_key_bio

    #save_key_der = RSA.save_pub_key_der

    #save_key_der_bio = RSA.save_pub_key_der_bio

    def check_key(self):
        return m2.rsa_check_pub_key(self.rsa)


def rsa_error():
    raise RSAError, m2.err_reason_error_string(m2.err_get_error())

def keygen_callback(p, n, out=sys.stdout):
    """
    Default callback for gen_key().
    """
    ch = ['.','+','*','\n']
    out.write(ch[p])
    out.flush()


def gen_key(bits, e, callback=keygen_callback):
    """
    Factory function that generates an RSA key pair and instantiates 
    an RSA object from it.
    
    _bits_ is the key length in bits.

    _e_ is the value for e, the RSA public exponent.

    (Optional) _callback_ is a Python callback object that will be
    invoked during key generation; its usual purpose is to provide visual
    feedback.
    """ 
    return RSA(m2.rsa_generate_key(bits, e, callback), 1)


def load_key(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates an RSA object.

    _file_ contains the PEM representation of the RSA key pair. 

    (Optional) _callback_ is a Python callback object that will be 
    invoked if the RSA key pair is passphrase-protected.
    """
    bio = BIO.openfile(file)
    return load_key_bio(bio, callback)


def load_key_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates an RSA object.

    The argument 'bio' is an M2Crypto.BIO object that contains the PEM
    representation of the RSA key pair. 

    The argument 'callback' is a Python callback object that will be invoked if
    the RSA key pair is passphrase-protected.
    """
    rsa = m2.rsa_read_key(bio._ptr(), callback)
    if rsa is None:
        rsa_error()
    return RSA(rsa, 1)


def load_pub_key(file):
    """
    Factory function that instantiates an RSA_pub object.

    The argument 'file' contains the PEM representation of the RSA public key.
    """
    bio = BIO.openfile(file) 
    return load_pub_key_bio(bio)


def load_pub_key_bio(bio):
    """
    Factory function that instantiates an RSA_pub object.

    The argument 'bio' is an M2Crypto.BIO object that contains the PEM
    representation of the RSA public key.
    """ 
    rsa = m2.rsa_read_pub_key(bio._ptr())
    if rsa is None:
        rsa_error()
    return RSA_pub(rsa, 1)


def new_pub_key((e, n)):
    """
    Factory function that instantiates an RSA_pub object from a (e, n) tuple.

    'e' is the RSA public exponent; it is a string in OpenSSL's MPINT format,
    i.e., 4-byte big-endian bit-count followed by the appropriate number of
    bits.

    'n' is the RSA composite of primes; it is a string in OpenSSL's MPINT format,
    i.e., 4-byte big-endian bit-count followed by the appropriate number of
    bits.
    """ 
    rsa = m2.rsa_new()
    m2.rsa_set_e(rsa, e)
    m2.rsa_set_n(rsa, n)
    return RSA_pub(rsa, 1)


