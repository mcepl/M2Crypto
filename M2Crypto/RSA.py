"""M2Crypto wrapper for OpenSSL RSA API.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: RSA.py,v 1.5 2000/11/19 07:37:48 ngps Exp $'

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
        self.rsa = rsa
        self._pyfree = _pyfree

    def __del__(self):
        try:
            if self._pyfree:
                m2.rsa_free(self.rsa)
        except AttributeError:
            pass

    def __len__(self):
        return m2.rsa_size(self.rsa)

    def __getattr__(self, name):
        if name == 'e':
            return m2.rsa_get_e(self.rsa)
        elif name == 'n':
            return m2.rsa_get_n(self.rsa)
        else:
            raise AttributeError

    def pub(self):
        return m2.rsa_get_e(self.rsa), m2.rsa_get_n(self.rsa)

    def public_encrypt(self, data, padding):
        return m2.rsa_public_encrypt(self.rsa, data, padding)

    def public_decrypt(self, data, padding):
        return m2.rsa_public_decrypt(self.rsa, data, padding)

    def private_encrypt(self, data, padding):
        return m2.rsa_private_encrypt(self.rsa, data, padding)

    def private_decrypt(self, data, padding):
        return m2.rsa_private_decrypt(self.rsa, data, padding)

    def save_key_bio(self, bio, cipher='des_ede3_cbc', callback=util.passphrase_callback):
        """
        Save the key pair to the M2Crypto.BIO object 'bio' in PEM format.
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
        Save the key pair to filename 'file' in PEM format.
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
                'use the factory function \'new_pub_key()\' to set (e, n)'
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


def keygen_callback(p, n, out=sys.stdout):
    """
    Default callback for gen_key().
    """
    if p == 0:
        out.write('.')
    elif p == 1:
        out.write('+')
    elif p == 2:
        out.write('*')
    elif p == 3:
        out.write('\n')
    out.flush()


def gen_key(bits, e, callback=keygen_callback):
    """
    Factory function that generates an RSA key pair and instantiates 
    an RSA object from it.
    
    The argument 'bits' is the key length.

    The argument 'e' is the value for e, the RSA public exponent.

    The optional argument 'callback' is a Python callback object that will be
    invoked during key generation; its usual purpose is to provide visual
    feedback.
    """ 
    return RSA(m2.rsa_generate_key(bits, e, callback), 1)


def load_key(file, callback=util.passphrase_callback):
    """
    Factory function that instantiates an RSA object.

    The argument 'file' contains the PEM representation of the 
    RSA key pair. 

    The argument 'callback' is a Python callback object
    that will be invoked if the RSA key pair is passphrase-protected.
    """
    bio = BIO.openfile(file)
    return RSA(m2.rsa_read_key(bio._ptr(), callback), 1)


def load_key_bio(bio, callback=util.passphrase_callback):
    """
    Factory function that instantiates an RSA object.

    The argument 'bio' is an M2Crypto.BIO object that contains the PEM
    representation of the RSA key pair. 

    The argument 'callback' is a Python callback object that will be invoked if
    the RSA key pair is passphrase-protected.
    """
    return RSA(m2.rsa_read_key(bio._ptr(), callback), 1)


def load_pub_key(file):
    """
    Factory function that instantiates an RSA_pub object.

    The argument 'file' contains the PEM representation of the RSA public key.
    """
    bio = BIO.openfile(file) 
    return RSA_pub(m2.rsa_read_pub_key(bio._ptr()), 1)


def load_pub_key_bio(bio):
    """
    Factory function that instantiates an RSA_pub object.

    The argument 'bio' is an M2Crypto.BIO object that contains the PEM
    representation of the RSA public key.
    """ 
    return RSA_pub(m2.rsa_read_pub_key(bio._ptr()), 1)


def new_pub_key(e, n):
    """
    Factory function that instantiates an RSA_pub object from a (e, n) tuple.
    """ 
    rsa = m2.rsa_new()
    m2.rsa_set_e(rsa, e)
    m2.rsa_set_n(rsa, n)
    return RSA_pub(rsa, 1)


