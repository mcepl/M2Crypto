"""M2Crypto PGP2 RSA.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: RSA.py,v 1.1 1999/12/22 15:51:53 ngps Exp $'

from M2Crypto import RSA, M2Crypto
m2=M2Crypto

class _RSA(RSA.RSA):
    pass

class _RSA_pub(RSA.RSA_pub):
    def __setattr__(self, name, value):
        # XXX Raise exception if e or n are not in order.
        if name=='e':
            return m2.rsa_set_e_bin(self.this, value)
        elif name=='n':
            return m2.rsa_set_n_bin(self.this, value)
        else:
            self.__dict__[name]=value
        
def new_pub_key(e, n):
    cptr=m2.rsa_new()
    r=_RSA_pub(cptr)
    r.e=e
    r.n=n
    return r

