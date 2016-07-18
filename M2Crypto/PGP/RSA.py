"""M2Crypto PGP2 RSA.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from M2Crypto import m2, util
from M2Crypto.RSA import RSA, RSA_pub  # noqa
if util.py27plus:
    from typing import Tuple  # noqa


def new_pub_key(e_n):
    # type: (Tuple[int, int]) -> RSA_pub
    """
    Factory function that instantiates an RSA_pub object from a (e, n) tuple.

    'e' is the RSA public exponent; it is a string in OpenSSL's binary format,
    i.e., a number of bytes in big-endian.

    'n' is the RSA composite of primes; it is a string in OpenSSL's
        binary format, i.e., a number of bytes in big-endian.
    """
    import warnings
    warnings.warn('Deprecated. No maintainer for PGP. If you use this, please inform M2Crypto maintainer.', DeprecationWarning)

    (e, n) = e_n
    rsa = m2.rsa_new()
    m2.rsa_set_e_bin(rsa, e)
    m2.rsa_set_n_bin(rsa, n)
    return RSA_pub(rsa, 1)
