"""M2Crypto wrapper for OpenSSL RC4 API.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

from m2 import rc4_new, rc4_free, rc4_set_key, rc4_update

class RC4:

    """Object interface to the stream cipher RC4."""

    def __init__(self, key=None):
        self.cipher = rc4_new()
        if key:
            rc4_set_key(self.cipher, key)

    def __del__(self):
        try:
            rc4_free(self.cipher)
        except AttributeError:
            pass

    def set_key(self, key):
        rc4_set_key(self.cipher, key)   

    def update(self, data):
        return rc4_update(self.cipher, data)

    def final(self):
        return ''


