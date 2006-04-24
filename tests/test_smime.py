#!/usr/bin/env python

"""Unit tests for M2Crypto.SMIME.

Copyright (C) 2006 Open Source Applications Foundation. All Rights Reserved.
"""

import unittest
from M2Crypto import SMIME, BIO, Rand, X509

cleartext = 'some text to manipulate'
signature = signature2 = None
encrypted = encrypted2 = None
signedEncrypted = None

class SMIMETestCase(unittest.TestCase):
    def check_1_sign(self):
        global signature, signature2
        
        buf = BIO.MemoryBuffer(cleartext)
        s = SMIME.SMIME()
        s.load_key('signer_key.pem', 'signer.pem')
        p7 = s.sign(buf)
        assert len(buf) == 0
        assert p7.type() == SMIME.PKCS7_SIGNED, p7.type()
        assert isinstance(p7, SMIME.PKCS7), p7
        #assert p7.get0_signers()
        out = BIO.MemoryBuffer()
        p7.write(out)
        
        buf = out.read()
        
        assert buf[:len('-----BEGIN PKCS7-----')] == '-----BEGIN PKCS7-----'
        #assert buf[-len('-----END PKCS7-----'):] == '-----END PKCS7-----'
        assert len(buf) > len('-----END PKCS7-----') + len('-----BEGIN PKCS7-----')
        
        s.write(out, p7, BIO.MemoryBuffer(cleartext))
        signature = out
        # another copy...
        s.write(out, p7, BIO.MemoryBuffer(cleartext))
        signature2 = out
    
    def check_2_verify(self):
        s = SMIME.SMIME()
        
        x509 = X509.load_cert('signer.pem')
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)
        
        st = X509.X509_Store()
        st.load_info('ca.pem')
        s.set_x509_store(st)
        
        p7, data = SMIME.smime_load_pkcs7_bio(signature)
        assert data.read() == cleartext
        assert isinstance(p7, SMIME.PKCS7), p7
        v = s.verify(p7)
        assert v == cleartext
    
    def _check_2_verifyBad(self):
        s = SMIME.SMIME()
        
        x509 = X509.load_cert('recipient.pem')
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)
        
        st = X509.X509_Store()
        st.load_info('recipient.pem')
        s.set_x509_store(st)
        
        p7, data = SMIME.smime_load_pkcs7_bio(signature2)
        assert data.read() == cleartext
        assert isinstance(p7, SMIME.PKCS7), p7
        self.assertRaises(SMIME.SMIME_Error, s.verify, p7) # Bad signer

    def check_3_encrypt(self):
        global encrypted, encrypted2
        
        buf = BIO.MemoryBuffer(cleartext)
        s = SMIME.SMIME()

        x509 = X509.load_cert('recipient.pem')
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
        p7 = s.encrypt(buf)
        
        assert len(buf) == 0
        assert p7.type() == SMIME.PKCS7_ENVELOPED, p7.type()
        assert isinstance(p7, SMIME.PKCS7), p7
        #assert p7.get0_signers()
        out = BIO.MemoryBuffer()
        p7.write(out)
    
        buf = out.read()
        
        assert buf[:len('-----BEGIN PKCS7-----')] == '-----BEGIN PKCS7-----'
        #assert buf[-len('-----END PKCS7-----'):] == '-----END PKCS7-----'
        assert len(buf) > len('-----END PKCS7-----') + len('-----BEGIN PKCS7-----')
        
        s.write(out, p7)
        encrypted = out
        # another copy...
        s.write(out, p7)
        encrypted2 = out

    def check_4_decrypt(self):
        s = SMIME.SMIME()

        s.load_key('recipient_key.pem', 'recipient.pem')
        
        p7, data = SMIME.smime_load_pkcs7_bio(encrypted)
        assert isinstance(p7, SMIME.PKCS7), p7
        self.assertRaises(SMIME.SMIME_Error, s.verify, p7) # No signer
        
        out = s.decrypt(p7)
        assert out == cleartext

    def _check_4_decryptBad(self):
        s = SMIME.SMIME()

        s.load_key('signer_key.pem', 'signer.pem')
        
        p7, data = SMIME.smime_load_pkcs7_bio(encrypted2)
        assert isinstance(p7, SMIME.PKCS7), p7
        self.assertRaises(SMIME.SMIME_Error, s.verify, p7) # No signer

        # Cannot decrypt: no recipient matches certificate
        self.assertRaises(SMIME.PKCS7_Error, s.decrypt, p7)

    def check_5_signEncrypt(self):
        global signedEncrypted
        
        s = SMIME.SMIME()
        
        buf = BIO.MemoryBuffer(cleartext)
        
        s.load_key('signer_key.pem', 'signer.pem')
        p7 = s.sign(buf)
        
        x509 = X509.load_cert('recipient.pem')
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)
    
        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
        
        tmp = BIO.MemoryBuffer()
        
        s.write(tmp, p7)
        
        p7 = s.encrypt(tmp)
        # XXX Hmm, how to get PKCS7_SIGNED_ENVELOPED?
        assert p7.type() == SMIME.PKCS7_ENVELOPED, p7.type()
        
        out = BIO.MemoryBuffer()
        s.write(out, p7)
        
        signedEncrypted = out
        
    def _check_6_decryptVerify(self):
        s = SMIME.SMIME()
    
        s.load_key('recipient_key.pem', 'recipient.pem')
        
        # XXX Bug not enough data?
        p7, data = SMIME.smime_load_pkcs7_bio(signedEncrypted)
        
        out = s.decrypt(p7)
        
        x509 = X509.load_cert('signer.pem')
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)
        
        st = X509.X509_Store()
        st.load_info('signer.pem')
        s.set_x509_store(st)
        
        p7_bio = BIO.MemoryBuffer(out)
        p7, data = SMIME.smime_load_pkcs7_bio(p7_bio)
        v = s.verify(p7)
        assert v == cleartext
    

def suite():
    return unittest.makeSuite(SMIMETestCase, 'check')


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')

