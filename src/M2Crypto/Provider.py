# vim: sts=4 sw=4 et
from __future__ import absolute_import

"""
M2Crypto wrapper for OpenSSL PROVIDER API.
"""

from M2Crypto import EVP, X509, m2

class Provider(object):
    """Wrapper for PROVIDER object."""

    def __init__(self, _id: str):
        self._ptr = m2.provider_load(_id)

    def __del__(self) -> None:
        m2.provider_unload(self._ptr)

    def load_key(self, uri: str) -> EVP.PKey:
        """Load a private or public key with provider methods (e.g from smartcard).
        """
        assert (type(uri) == str), f"Wrong type {type(uri)} != str for uri"
        uri_split_list = uri.split(';')
        assert ('type=private' in uri_split_list or 'type=public' in uri_split_list), "Key URI should indicate 'type=private' or 'type=public'"
        cptr = m2.provider_load_key(uri)
        if not cptr:
            raise ValueError("Key or card not found")
        return EVP.PKey(cptr, _pyfree=1)

    def load_certificate(self, uri: str) -> X509.X509:
        """Load certificate from provider (e.g from smartcard).
        """
        assert (type(uri) == str), f"Wrong type {type(uri)} != str for uri"
        cptr = m2.provider_load_certificate(uri)
        if not cptr:
            raise ValueError("Certificate or card not found")
        return X509.X509(cptr, _pyfree=1)
