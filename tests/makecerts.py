#!/usr/bin/env python
#
# Create test certificates:
#
#  ca.pem
#  server.pem
#  recipient.pem
#  signer.pem
#  x509.pem
#

import time
from M2Crypto import X509, RSA, EVP, ASN1, m2

t = long(time.time()) + time.timezone
before = ASN1.ASN1_UTCTIME()
before.set_time(t)
after = ASN1.ASN1_UTCTIME()
after.set_time(t + 60 * 60 * 24 * 365 * 10) # 10 years

serial = 1

def callback(self, *args):
    return ' '

def req(name):
    rsa = RSA.load_key(name + '_key.pem')
    pk = EVP.PKey()
    pk.assign_rsa(rsa)
    req = X509.Request()
    req.set_pubkey(pk)
    n = req.get_subject()
    n.C = 'US'
    n.O = 'M2Crypto ' + name 
    n.CN = 'localhost'
    req.sign(pk, 'sha256')
    return req, pk

def saveTextPemKey(cert, name):
    f = open(name + '.pem', 'wb')
    for line in cert.as_text():
        f.write(line)
    for line in cert.as_pem():
        f.write(line)
    for line in open(name + '_key.pem', 'rb'):
        f.write(line)
    f.close()

def issue(request, ca, capk):
    global serial
    
    pkey = request.get_pubkey()
    sub = request.get_subject()

    cert = X509.X509()
    cert.set_version(2)
    cert.set_subject(sub)
    cert.set_serial_number(serial)
    serial += 1

    issuer = ca.get_subject()
    cert.set_issuer(issuer)
    
    cert.set_pubkey(pkey)     

    cert.set_not_before(before)
    cert.set_not_after(after)

    cert.sign(capk, 'sha256')
    
    assert cert.verify(capk)
    
    return cert

def mk_ca():
    r, pk = req('ca')
    pkey = r.get_pubkey()
    sub = r.get_subject()

    cert = X509.X509()
    cert.set_version(2)
    cert.set_subject(sub)
    cert.set_serial_number(0)

    issuer = X509.X509_Name()
    issuer.C = sub.C
    issuer.O = sub.O
    issuer.CN = sub.CN
    cert.set_issuer(issuer)
    
    cert.set_pubkey(pkey)     

    cert.set_not_before(before)
    cert.set_not_after(after)

    ext = X509.new_extension('basicConstraints', 'CA:TRUE')
    cert.add_ext(ext)
    
    cert.sign(pk, 'sha256')
    
    saveTextPemKey(cert, 'ca')
    
    return cert, pk

def mk_server(ca, capk):
    r, pk = req('server')
    cert = issue(r, ca, capk)
    saveTextPemKey(cert, 'server')

def mk_x509(ca, capk):
    r, pk = req('x509')
    cert = issue(r, ca, capk)
    saveTextPemKey(cert, 'x509')

def mk_signer(ca, capk):
    r, pk = req('signer')
    r.get_subject().Email = 'signer@example.com'
    cert = issue(r, ca, capk)
    saveTextPemKey(cert, 'signer')

def mk_recipient(ca, capk):
    r, pk = req('recipient')
    r.get_subject().Email = 'recipient@example.com'
    cert = issue(r, ca, capk)
    saveTextPemKey(cert, 'recipient')

if __name__ == '__main__':
    names = ['ca', 'server', 'recipient', 'signer', 'x509']

    for name in names:
        rsa = RSA.gen_key(2048, m2.RSA_F4)
        rsa.save_key('%s_key.pem' % name, None)
    
    ca, pk = mk_ca()
    mk_server(ca, pk)
    mk_x509(ca, pk)
    mk_signer(ca, pk)
    mk_recipient(ca, pk)
