"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Cipher.py,v 1.1 2000/02/23 15:33:22 ngps Exp $'

from M2Crypto import M2Crypto 
m2 = M2Crypto

class Cipher:
    def __init__(self, cipher):
        self.cipher=cipher

    def __len__(self):
        return m2.ssl_cipher_get_bits(self.cipher)

    def version(self):
        return m2.ssl_cipher_get_version(self.cipher)

    def name(self):
        return m2.ssl_cipher_get_name(self.cipher)


class Cipher_Stack:
    def __init__(self, stack):
        self.stack=stack

    def __len__(self):
        return m2.sk_ssl_cipher_num(self.stack)

    def __getitem__(self, idx):
        if idx < 0 or idx >= m2.sk_ssl_cipher_num(self.stack):
            raise IndexError, 'index out of range'
        v=m2.sk_ssl_cipher_value(self.stack, idx)
        return Cipher(v)

