#!/usr/bin/env python

"""Unit tests for M2Crypto.X509.

Contributed by Toby Allsopp <toby@MI6.GEN.NZ> under M2Crypto's license.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2005 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

import unittest
import os, time, base64, sys
from M2Crypto import X509, EVP, RSA, Rand, ASN1, m2, util

class X509TestCase(unittest.TestCase):

    def callback(self, *args):
        pass

    def mkreq(self, bits, ca=0):
        pk = EVP.PKey()
        x = X509.Request()
        rsa = RSA.gen_key(bits, 65537, self.callback)
        pk.assign_rsa(rsa)
        rsa = None # should not be freed here
        x.set_pubkey(pk)
        name = x.get_subject()
        name.C = "UK"
        name.CN = "OpenSSL Group"
        if not ca:
            ext1 = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
            ext2 = X509.new_extension('nsComment', 'Hello there')
            extstack = X509.X509_Extension_Stack()
            extstack.push(ext1)
            extstack.push(ext2)
            x.add_extensions(extstack)
        self.assertRaises(ValueError, x.sign, pk, 'sha513')
        x.sign(pk,'md5')
        assert x.verify(pk)
        pk2 = x.get_pubkey()
        assert x.verify(pk2)
        return x, pk

    def check_ext(self):
        self.assertRaises(ValueError, X509.new_extension,
                          'subjectKeyIdentifier', 'hash')

    def check_extstack(self):
        # new
        ext1 = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
        ext2 = X509.new_extension('nsComment', 'Hello there')
        extstack = X509.X509_Extension_Stack()
        
        # push
        extstack.push(ext1)
        extstack.push(ext2)
        assert(extstack[1].get_name() == 'nsComment')
        assert len(extstack) == 2
        
        # iterator
        i = 0
        for e in extstack:
            i += 1
            assert len(e.get_name()) > 0
        assert i == 2
        
        # pop
        ext3 = extstack.pop()
        assert len(extstack) == 1
        assert(extstack[0].get_name() == 'subjectAltName')
        extstack.push(ext3)
        assert len(extstack) == 2
        assert(extstack[1].get_name() == 'nsComment')

    def check_x509_name(self):
        n = X509.X509_Name()
        n.C = 'US' # It seems this actually needs to be a real 2 letter country code
        assert n.C == 'US'
        n.SP = 'State or Province'
        assert n.SP == 'State or Province'
        n.L = 'locality name'
        assert n.L == 'locality name'
        n.O = 'orhanization name'
        assert n.O == 'orhanization name'
        n.OU = 'org unit'
        assert n.OU == 'org unit'
        n.CN = 'common name'
        assert n.CN == 'common name'
        n.Email = 'bob@example.com'
        assert n.Email == 'bob@example.com'
        n.serialNumber = '1234'
        assert n.serialNumber == '1234'
        n.SN = 'surname'
        assert n.SN == 'surname'
        n.GN = 'given name'
        assert n.GN == 'given name'
        assert n.as_text() == 'C=US, ST=State or Province, L=locality name, O=orhanization name, OU=org unit, CN=common name/emailAddress=bob@example.com/serialNumber=1234, SN=surname, GN=given name', '"%s"' % n.as_text()
        assert len(n) == 10, len(n)
        n.givenName = 'name given'
        assert n.GN == 'given name' # Just gets the first
        assert n.as_text() == 'C=US, ST=State or Province, L=locality name, O=orhanization name, OU=org unit, CN=common name/emailAddress=bob@example.com/serialNumber=1234, SN=surname, GN=given name, GN=name given', '"%s"' % n.as_text()
        assert len(n) == 11, len(n)
        n.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                           entry="Proxy", len=-1, loc=-1, set=0)
        assert len(n) == 12, len(n)
        assert n.as_text() == 'C=US, ST=State or Province, L=locality name, O=orhanization name, OU=org unit, CN=common name/emailAddress=bob@example.com/serialNumber=1234, SN=surname, GN=given name, GN=name given, CN=Proxy', '"%s"' % n.as_text()

        self.assertRaises(AttributeError, n.__getattr__, 'foobar')
        n.foobar = 1
        assert n.foobar == 1, n.foobar
                           
                           
    def check_mkreq(self):
        (req, _) = self.mkreq(512)
        req.save_pem('tests/tmp_request.pem')
        req2 = X509.load_request('tests/tmp_request.pem')
        os.remove('tests/tmp_request.pem')
        assert req.as_pem() == req2.as_pem()
        assert req.as_text() == req2.as_text()

    def check_mkcert(self):
        req, pk = self.mkreq(512)
        pkey = req.get_pubkey()
        assert(req.verify(pkey))
        sub = req.get_subject()
        assert len(sub) == 2, len(sub)
        cert = X509.X509()
        cert.set_serial_number(1)
        cert.set_version(2)
        cert.set_subject(sub)
        t = long(time.time()) + time.timezone
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        nowPlusYear = ASN1.ASN1_UTCTIME()
        nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
        cert.set_not_before(now)
        cert.set_not_after(nowPlusYear)
        assert str(cert.get_not_before()) == str(now)
        assert str(cert.get_not_after()) == str(nowPlusYear)
        issuer = X509.X509_Name()
        issuer.CN = 'The Issuer Monkey'
        issuer.O = 'The Organization Otherwise Known as My CA, Inc.'
        cert.set_issuer(issuer)
        cert.set_pubkey(pkey)
        cert.set_pubkey(cert.get_pubkey()) # Make sure get/set work
        ext = X509.new_extension('subjectAltName', 'DNS:foobar.example.com')
        ext.set_critical(0)
        cert.add_ext(ext)
        cert.sign(pk, 'sha1')
        assert(cert.get_ext('subjectAltName').get_name() == 'subjectAltName')
        assert(cert.get_ext_at(0).get_name() == 'subjectAltName')
        assert(cert.get_ext_at(0).get_value() == 'DNS:foobar.example.com')
        assert cert.get_ext_count() == 1, cert.get_ext_count()
        assert cert.verify()
        assert cert.verify(pkey)
        assert cert.verify(cert.get_pubkey())
        
        if m2.OPENSSL_VERSION_NUMBER >= 0x90800f:
            assert not cert.check_ca()
            assert not cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 1)
            assert not cert.check_purpose(m2.X509_PURPOSE_NS_SSL_SERVER, 1)
            assert cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 0)
            assert cert.check_purpose(m2.X509_PURPOSE_NS_SSL_SERVER, 0)
            assert cert.check_purpose(m2.X509_PURPOSE_ANY, 0)            
        else:
            self.assertRaises(AttributeError, cert.check_ca)

    def mkcacert(self):
        req, pk = self.mkreq(512, ca=1)
        pkey = req.get_pubkey()
        sub = req.get_subject()
        cert = X509.X509()
        cert.set_serial_number(1)
        cert.set_version(2)
        cert.set_subject(sub)
        t = long(time.time()) + time.timezone
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        nowPlusYear = ASN1.ASN1_UTCTIME()
        nowPlusYear.set_time(t + 60 * 60 * 24 * 365)
        cert.set_not_before(now)
        cert.set_not_after(nowPlusYear)
        issuer = X509.X509_Name()
        issuer.C = "UK"
        issuer.CN = "OpenSSL Group"
        cert.set_issuer(issuer)
        cert.set_pubkey(pkey) 
        ext = X509.new_extension('basicConstraints', 'CA:TRUE')
        cert.add_ext(ext)
        cert.sign(pk, 'sha1')

        if m2.OPENSSL_VERSION_NUMBER >= 0x0090800fL:
            assert cert.check_ca()
            assert cert.check_purpose(m2.X509_PURPOSE_SSL_SERVER, 1)
            assert cert.check_purpose(m2.X509_PURPOSE_NS_SSL_SERVER, 1)
            assert cert.check_purpose(m2.X509_PURPOSE_ANY, 1)
        else:
            self.assertRaises(AttributeError, cert.check_ca)
        
        return cert, pk, pkey

    def check_mkcacert(self): 
        cacert, pk, pkey = self.mkcacert()
        assert cacert.verify(pkey)
        

    def check_mkproxycert(self): 
        cacert, pk1, pkey = self.mkcacert()
        end_entity_cert_req, pk2 = self.mkreq(512)
        end_entity_cert = self.make_eecert(cacert)
        end_entity_cert.set_subject(end_entity_cert_req.get_subject())
        end_entity_cert.set_pubkey(end_entity_cert_req.get_pubkey())
        end_entity_cert.sign(pk1, 'sha1')
        proxycert = self.make_proxycert(end_entity_cert)
        proxycert.sign(pk2, 'sha1')
        assert proxycert.verify(pk2)
        assert proxycert.get_ext_at(0).get_name() == 'proxyCertInfo', proxycert.get_ext_at(0).get_name()
        assert proxycert.get_ext_at(0).get_value() == 'Path Length Constraint: infinite\nPolicy Language: Inherit all\n', '"%s"' % proxycert.get_ext_at(0).get_value()
        assert proxycert.get_ext_count() == 1, proxycert.get_ext_count()
        assert proxycert.get_subject().as_text() == 'C=UK, CN=OpenSSL Group, CN=Proxy', proxycert.get_subject().as_text()
        assert proxycert.get_subject().as_text(indent=2, flags=m2.XN_FLAG_RFC2253) == '  CN=Proxy,CN=OpenSSL Group,C=UK', '"%s"' %  proxycert.get_subject().as_text(indent=2, flags=m2.XN_FLAG_RFC2253)

    def make_eecert(self, cacert):
        eecert = X509.X509()
        eecert.set_serial_number(2)
        eecert.set_version(2)
        t = long(time.time()) + time.timezone
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        now_plus_year = ASN1.ASN1_UTCTIME()
        now_plus_year.set_time(t + 60 * 60 * 24 * 365)
        eecert.set_not_before(now)
        eecert.set_not_after(now_plus_year)
        eecert.set_issuer(cacert.get_subject())
        return eecert
    
    def make_proxycert(self, eecert):
        proxycert = X509.X509()
        pk2 = EVP.PKey()
        proxykey =  RSA.gen_key(512, 65537, self.callback)
        pk2.assign_rsa(proxykey)
        proxycert.set_pubkey(pk2)
        proxycert.set_version(2)
        not_before = ASN1.ASN1_UTCTIME()
        not_after = ASN1.ASN1_UTCTIME()
        not_before.set_time(int(time.time()))
        offset = 12 * 3600
        not_after.set_time(int(time.time()) + offset )
        proxycert.set_not_before(not_before)
        proxycert.set_not_after(not_after)
        proxycert.set_issuer_name(eecert.get_subject())
        proxycert.set_serial_number(12345678)
        proxy_subject_name = X509.X509_Name()
        issuer_name_string = eecert.get_subject().as_text()
        seq = issuer_name_string.split(",")

        subject_name = X509.X509_Name()
        for entry in seq:
            l = entry.split("=")
            subject_name.add_entry_by_txt(field=l[0].strip(),
                                          type=ASN1.MBSTRING_ASC,
                                          entry=l[1], len=-1, loc=-1, set=0)

        subject_name.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                                      entry="Proxy", len=-1, loc=-1, set=0)


        proxycert.set_subject_name(subject_name)
        pci_ext = X509.new_extension("proxyCertInfo", 
                                     "critical,language:Inherit all", 1, 0)
        proxycert.add_ext(pci_ext)
        return proxycert
    
    def check_fingerprint(self):
        x509 = X509.load_cert('tests/x509.pem')
        fp = x509.get_fingerprint('sha1')
        expected = '128858B5222A5C78397530A5706233A9EB470AC4'
        assert fp == expected, '%s != %s' % (fp, expected)


class X509_StackTestCase(unittest.TestCase):
    
    def check_make_stack_from_der(self):
        f = open("tests/der_encoded_seq.b64")
        b64 = f.read(1304)
        seq = base64.decodestring(b64)
        stack = X509.new_stack_from_der(seq)
        cert = stack.pop()
        
        subject = cert.get_subject() 
        assert str(subject) == "/DC=org/DC=doegrids/OU=Services/CN=host/bosshog.lbl.gov"
    
    def check_make_stack_check_num(self):
        f = open("tests/der_encoded_seq.b64")
        b64 = f.read(1304)
        seq = base64.decodestring(b64)
        stack = X509.new_stack_from_der(seq)
        num = len(stack)
        assert num == 1 
        cert = stack.pop() 
        num = len(stack)
        assert num == 0 
        subject = cert.get_subject() 
        assert str(subject) == "/DC=org/DC=doegrids/OU=Services/CN=host/bosshog.lbl.gov"

    def check_make_stack(self):
        stack = X509.X509_Stack()
        cert = X509.load_cert("tests/x509.pem")
        issuer = X509.load_cert("tests/ca.pem")
        cert_subject1 = cert.get_subject()
        issuer_subject1 = issuer.get_subject()
        stack.push(cert)
        stack.push(issuer)
        
        # Test stack iterator
        i = 0
        for c in stack:
            i += 1
            assert len(c.get_subject().CN) > 0
        assert i == 2
        
        issuer_pop = stack.pop() 
        cert_pop = stack.pop() 
        cert_subject2 = cert_pop.get_subject() 
        issuer_subject2 = issuer.get_subject()
        assert str(cert_subject1) == str(cert_subject2)
        assert str(issuer_subject1) == str(issuer_subject2)
    
    def check_as_der(self):
        stack = X509.X509_Stack()
        cert = X509.load_cert("tests/x509.pem")
        issuer = X509.load_cert("tests/ca.pem")
        cert_subject1 = cert.get_subject()
        issuer_subject1 = issuer.get_subject()
        stack.push(cert)
        stack.push(issuer)
        der_seq = stack.as_der() 
        stack2 = X509.new_stack_from_der(der_seq)
        issuer_pop = stack2.pop() 
        cert_pop = stack2.pop() 
        cert_subject2 = cert_pop.get_subject() 
        issuer_subject2 = issuer.get_subject()
        assert str(cert_subject1) == str(cert_subject2)
        assert str(issuer_subject1) == str(issuer_subject2)
        

def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(X509TestCase, 'check'))
    suite.addTest(unittest.makeSuite(X509_StackTestCase, 'check'))
    return suite


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
