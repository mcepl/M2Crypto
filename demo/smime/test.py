#!/usr/bin/env python

"""S/MIME demo.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: test.py,v 1.1 2000/04/01 15:08:30 ngps Exp $'

from M2Crypto import BIO, SMIME, X509

ptxt = 'pgp -vs- smime'

def makebuf():
    buf = BIO.MemoryBuffer(ptxt)
    return buf

def sign():
    print 'test sign & save...',
    buf = makebuf()
    s = SMIME.SMIME()
    s.load_key('client.pem')
    p7 = s.sign(buf)
    out = BIO.openfile('p7.clear', 'w')
    out.write('To: ngps@post1.com\n')
    out.write('From: m2crypto@m2crypto.org\n')
    out.write('Subject: testing\n')
    buf = makebuf() # Recreate buf, because sign() has consumed it.
    s.write(out, p7, buf)
    out.close()

    buf = makebuf()
    p7 = s.sign(buf)
    out = BIO.openfile('p7.opaque', 'w')
    out.write('To: ngps@post1.com\n')
    out.write('From: m2crypto@m2crypto.org\n')
    out.write('Subject: testing\n')
    s.write(out, p7)
    out.close()
    print 'ok'

def verify_clear():
    print 'test load & verify clear...',
    s = SMIME.SMIME()
    x509 = X509.load_cert('client.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)
    st = X509.X509_Store()
    st.load_info('ca.pem')
    s.set_x509_store(st)
    p7, data = SMIME.load_pkcs7('p7.clear')
    v = s.verify(p7)
    if v == ptxt:
        print 'ok'
    else:
        print 'not ok'
    
def verify_opaque():
    print 'test load & verify opaque...',
    s = SMIME.SMIME()
    x509 = X509.load_cert('client.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)
    st = X509.X509_Store()
    st.load_info('ca.pem')
    s.set_x509_store(st)
    p7, data = SMIME.load_pkcs7('p7.opaque')
    v = s.verify(p7, data)
    if v == ptxt:
        print 'ok'
    else:
        print 'not ok'
    
def verify_netscape():
    print 'test load & verify netscape messager output...',
    s = SMIME.SMIME()
    #x509 = X509.load_cert('client.pem')
    sk = X509.X509_Stack()
    #sk.push(x509)
    s.set_x509_stack(sk)
    st = X509.X509_Store()
    st.load_info('ca.pem')
    s.set_x509_store(st)
    p7, data = SMIME.load_pkcs7('ns.p7')
    v = s.verify(p7, data)
    print '\n', v, '\n...ok'

    
def sv():
    print 'test sign/verify...',
    buf = makebuf()
    s = SMIME.SMIME()

    # Load a private key.
    s.load_key('client.pem')

    # Load signer cert(s).
    x509 = X509.load_cert('client.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Sign.
    p7 = s.sign(buf, SMIME.PKCS7_DETACHED)
    #p7 = s.sign(buf)
    
    # Construct verification plumbing.
    st = X509.X509_Store()
    st.load_info('ca.pem')
    s.set_x509_store(st)

    # Verify.
    buf = makebuf()
    v = s.verify(p7, buf, SMIME.PKCS7_DETACHED)
    
    if v:
        print 'ok'
    else:
        print 'not ok'

def ed():
    print 'test encrypt/decrypt...',
    buf = makebuf()
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert('client.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Add a cipher.
    s.set_cipher(SMIME.Cipher('bf_cbc')) 

    # Encrypt.
    p7 = s.encrypt(buf)
    
    # Load target's private key.
    s.load_key('client.pem')

    # Decrypt.
    data = s.decrypt(p7)
    
    if data == ptxt:
        print 'ok'
    else:
        print 'not ok'


if __name__ == '__main__':
    ed()
    #sv()
    sign()
    verify_opaque()
    verify_clear()
    verify_netscape()

