"""M2Crypto PGP2 RSA.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: RSA.py,v 1.2 2000/11/26 09:49:47 ngps Exp $'

import sys
from M2Crypto import m2

if sys.version[:3] == '2.0':
    from M2Crypto import RSA as _RSA

elif sys.version[:3] == '1.5':
    from M2Crypto import RSA
    _RSA = RSA
    del RSA

else:
    raise RuntimeError, 'unknown Python version'


class RSA(_RSA.RSA):
    pass


class RSA_pub(_RSA.RSA_pub):
    pass


def new_pub_key((e, n)):
    """
    Factory function that instantiates an RSA_pub object from a (e, n) tuple.

    'e' is the RSA public exponent; it is a string in OpenSSL's binary format,
    i.e., a number of bytes in big-endian.

    'n' is the RSA composite of primes; it is a string in OpenSSL's binary format,
    i.e., a number of bytes in big-endian.
    """ 
    rsa = m2.rsa_new()
    m2.rsa_set_e_bin(rsa, e)
    m2.rsa_set_n_bin(rsa, n)
    return RSA_pub(rsa, 1)

