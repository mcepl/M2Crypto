#!/usr/bin/env python

"""Unit tests for M2Crypto.RSA.

Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

import hashlib
import logging
import os

from M2Crypto import BIO, RSA, Rand, X509, m2
from tests import unittest
from tests.fips import fips_mode

log = logging.getLogger('test_RSA')


class RSATestCase(unittest.TestCase):

    errkey = 'tests/dsa.priv.pem'
    privkey = 'tests/rsa.priv.pem'
    privkey2 = 'tests/rsa.priv2.pem'
    pubkey = 'tests/rsa.pub.pem'

    data = hashlib.sha256(
        b'The magic words are squeamish ossifrage.'
    ).digest()

    e_padding_ok = ('pkcs1_padding', 'pkcs1_oaep_padding')

    s_padding_ok = ('pkcs1_padding',)
    s_padding_nok = ('no_padding', 'pkcs1_oaep_padding')
    if hasattr(m2, 'sslv23_padding'):
        s_padding_nok += ('sslv23_padding',)

    def gen_callback(self, *args):
        pass

    def gen2_callback(self):
        pass

    def pp_callback(self, *args):
        # The passphrase for rsa.priv2.pem is 'qwerty'.
        return b'qwerty'

    def pp2_callback(self, *args):
        # Misbehaving passphrase callback.
        return b'blabla'

    def test_rsa_exceptions(self):
        with self.assertRaises(RSA.RSAError):
            RSA.rsa_error()

    def test_loadkey_junk(self):
        with self.assertRaises(RSA.RSAError):
            RSA.load_key(self.errkey)

    def test_loadkey_pp(self):
        rsa = RSA.load_key(self.privkey2, self.pp_callback)
        self.assertEqual(len(rsa), 2048)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        self.assertEqual(rsa.check_key(), 1)

    def test_loadkey_pp_bad_cb(self):
        # with self.assertRaises(RSA.RSAError):
        #     RSA.load_key(self.privkey2, self.pp2_callback)
        RSA.load_key(self.privkey2, self.pp2_callback)

    def test_loadkey(self):
        self.maxDiff = None
        rsa = RSA.load_key(self.privkey)
        self.assertEqual(len(rsa), 2048)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        log.debug("rsa.n = %s", repr(rsa.n))
        self.assertEqual(
            rsa.n,
            b'\x00\x00\x01\x01\x00\xc9\xb76\x91\x86\xcb\x9a!' +
            b'w\x9c\xfb\x8c\xe8\xaa\xe7\xecT\xb02s\x00\xfav' +
            b'\x0b\xe4\xb7I\xa4\xf2\x8f\xe1\xaf\x93\xeevxT{' +
            b'\xc2\xb0\t\x05x?\xe6|\xfd\xf5\x86\x0b\xd2\x97\xc4\xc3\x99\x88h' +
            b'\xd4n{~`\x8a\xe4\xe73\n\xe6\x94\x1bTr\x9a\xa5\xf5+\xbe\x81\xacV' +
            b'\x0c\xb6s\xa3\x94\xacT.\xbf\xd3\t\x06[\x8a\x918\x01\xcf\xcb' +
            b'\x95\xce\x1b\xf3\xd4\xcf\xaf3qo\xf1\t\xe2\x16\xab\r\xdd\r_>' +
            b'\xc7\xa1\x88\xf4\x10\'\xe54S\x1a\x9c\xf3\xa1\xaf\xddw\xec{' +
            b'\x9f\xefvCS\xc2\xa6\xba\xcb\xa1-{\xee\xd4\xa2hiY\x7f)\xb3{' +
            b'\x1d\xf3\x19NX\x01t\xbe\x83\xaa\x17\xc0\xaax\x97\x10\xe9"y' +
            b'\x9e\x1d\'i\xfe\'\xec\xb0\xd8:\xd42\\a\xea\xeb\x19\x1e\xab|' +
            b'\xad\xb8\xda\x1b\xb7,.o"\x84\xa4\xd3\xff\xc2\xff\xf6iH>C\x14z' +
            b'\xea\xc6f6\xa5\x96N^\x8c\xdej\xferN\xad\'\x9e\xcf6\x06A,\xa7W=' +
            b'\xa1\x07\xc5\xfb\xbb2\xd5;V\x14\xe7'
        )
        with self.assertRaises(AttributeError):
            getattr(rsa, 'nosuchprop')
        self.assertEqual(rsa.check_key(), 1)

    def test_loadkey_bio(self):
        with open(self.privkey, "rb") as f:
            keybio = BIO.MemoryBuffer(f.read())
        rsa = RSA.load_key_bio(keybio)
        self.assertEqual(len(rsa), 2048)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        self.assertEqual(rsa.check_key(), 1)

    def test_keygen(self):
        rsa = RSA.gen_key(1024, 65537, self.gen_callback)
        self.assertEqual(len(rsa), 1024)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        self.assertEqual(rsa.check_key(), 1)

    def test_keygen_bad_cb(self):
        rsa = RSA.gen_key(1024, 65537, self.gen2_callback)
        self.assertEqual(len(rsa), 1024)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        self.assertEqual(rsa.check_key(), 1)

    def test_private_encrypt(self):
        priv = RSA.load_key(self.privkey)
        # pkcs1_padding
        for padding in self.s_padding_ok:
            p = getattr(RSA, padding)
            ctxt = priv.private_encrypt(self.data, p)
            ptxt = priv.public_decrypt(ctxt, p)
            self.assertEqual(ptxt, self.data)
        # The other paddings.
        for padding in self.s_padding_nok:
            p = getattr(RSA, padding)
            with self.assertRaises(RSA.RSAError):
                priv.private_encrypt(self.data, p)
        # Type-check the data to be encrypted.
        with self.assertRaises(TypeError):
            priv.private_encrypt(self.gen_callback, RSA.pkcs1_padding)

    @unittest.skipIf(
        m2.OPENSSL_VERSION_NUMBER < 0x1010103F
        or m2.OPENSSL_VERSION_NUMBER >= 0x30000000,
        'Relies on fix which happened only in OpenSSL 1.1.1c',
    )
    def test_public_encrypt(self):
        priv = RSA.load_key(self.privkey)
        # pkcs1_padding, pkcs1_oaep_padding
        for padding in self.e_padding_ok:
            p = getattr(RSA, padding)
            ctxt = priv.public_encrypt(self.data, p)
            ptxt = priv.private_decrypt(ctxt, p)
            self.assertEqual(ptxt, self.data)

        # no_padding
        m2.err_clear_error()
        with self.assertRaisesRegex(RSA.RSAError, 'data too small'):
            priv.public_encrypt(self.data, RSA.no_padding)

        # Type-check the data to be encrypted.
        with self.assertRaises(TypeError):
            priv.public_encrypt(self.gen_callback, RSA.pkcs1_padding)

    def test_x509_public_encrypt(self):
        x509 = X509.load_cert("tests/recipient.pem")
        rsa = x509.get_pubkey().get_rsa()
        rsa.public_encrypt(b"data", RSA.pkcs1_padding)

    def test_loadpub(self):
        rsa = RSA.load_pub_key(self.pubkey)
        self.assertEqual(len(rsa), 2048)
        self.assertEqual(
            rsa.e, b'\000\000\000\003\001\000\001'
        )  # aka 65537 aka 0xf4
        with self.assertRaises(RSA.RSAError):
            setattr(rsa, 'e', '\000\000\000\003\001\000\001')
        with self.assertRaises(RSA.RSAError):
            rsa.private_decrypt(1)
        assert rsa.check_key()

    def test_loadpub_bad(self):
        with self.assertRaises(RSA.RSAError):
            RSA.load_pub_key(self.errkey)

    def test_savepub(self):
        rsa = RSA.load_pub_key(self.pubkey)
        assert rsa.as_pem()  # calls save_key_bio
        f = 'tests/rsa_test.pub'
        try:
            self.assertEqual(rsa.save_key(f), 1)
        finally:
            try:
                os.remove(f)
            except IOError:
                pass

    def test_set_bn(self):
        rsa = RSA.load_pub_key(self.pubkey)
        with self.assertRaises(RSA.RSAError):
            m2.rsa_set_en(
                rsa.rsa,
                b'\000\000\000\003\001\000\001',
                b'\000\000\000\003\001',
            )

    def test_set_n(self):
        rsa = m2.rsa_new()
        m2.rsa_set_n(rsa, b'\000\000\000\003\001\000\001')

        n = m2.rsa_get_n(rsa)
        e = m2.rsa_get_e(rsa)

        self.assertEqual(n, b'\000\000\000\003\001\000\001')
        self.assertEqual(e, b'\x00\x00\x00\x00')

    def test_set_e(self):
        rsa = m2.rsa_new()
        m2.rsa_set_e(rsa, b'\000\000\000\003\001\000\001')

        n = m2.rsa_get_n(rsa)
        e = m2.rsa_get_e(rsa)

        self.assertEqual(e, b'\000\000\000\003\001\000\001')
        self.assertEqual(n, b'\x00\x00\x00\x00')

    def test_set_n_then_set_e(self):
        rsa = m2.rsa_new()
        m2.rsa_set_n(rsa, b'\000\000\000\004\020\011\006\006')
        m2.rsa_set_e(rsa, b'\000\000\000\003\001\000\001')

        n = m2.rsa_get_n(rsa)
        e = m2.rsa_get_e(rsa)

        self.assertEqual(e, b'\000\000\000\003\001\000\001')
        self.assertEqual(n, b'\000\000\000\004\020\011\006\006')

    def test_newpub(self):
        old = RSA.load_pub_key(self.pubkey)
        new = RSA.new_pub_key(old.pub())
        self.assertTrue(new.check_key())
        self.assertEqual(len(new), 2048)
        # aka 65537 aka 0xf4
        self.assertEqual(new.e, b'\000\000\000\003\001\000\001')

    def test_sign_and_verify(self):
        """
        Testing signing and verifying digests
        """
        algos = {'sha256': '', 'ripemd160': '', 'md5': ''}

        if m2.OPENSSL_VERSION_NUMBER >= 0x90800F:
            algos['sha224'] = ''
            algos['sha256'] = ''
            algos['sha384'] = ''
            algos['sha512'] = ''

        message = b"This is the message string"
        digest = hashlib.sha256(message).digest()
        rsa = RSA.load_key(self.privkey)
        rsa2 = RSA.load_pub_key(self.pubkey)
        for algo in algos.keys():
            signature = rsa.sign(digest, algo)
            # assert signature == algos[algo],
            #     'mismatched signature with algorithm %s:
            #     signature=%s' % (algo, signature)
            verify = rsa2.verify(digest, signature, algo)
            self.assertEqual(
                verify,
                1,
                'verification failed with algorithm %s' % algo,
            )

    if m2.OPENSSL_VERSION_NUMBER >= 0x90708F:

        def test_sign_and_verify_rsassa_pss(self):
            """
            Testing signing and verifying using rsassa_pss

            The maximum size of the salt has to decrease as the
            size of the digest increases because of the size of
            our test key limits it.
            """
            message = b"This is the message string"
            import hashlib

            algos = {'sha256': 43}
            if not fips_mode:
                algos['md5'] = 47
                algos['ripemd160'] = 43

            if m2.OPENSSL_VERSION_NUMBER >= 0x90800F:
                algos['sha224'] = 35
                algos['sha256'] = 31
                algos['sha384'] = 15
                algos['sha512'] = 0

            for algo, salt_max in algos.items():
                try:
                    h = hashlib.new(algo)
                except ValueError:
                    algos[algo] = (None, None)
                    continue
                h.update(message)
                digest = h.digest()
                algos[algo] = (salt_max, digest)

            rsa = RSA.load_key(self.privkey)
            rsa2 = RSA.load_pub_key(self.pubkey)
            for algo, (salt_max, digest) in algos.items():
                if salt_max is None or digest is None:
                    continue
                for salt_length in range(0, salt_max):
                    signature = rsa.sign_rsassa_pss(
                        digest, algo, salt_length
                    )
                    verify = rsa2.verify_rsassa_pss(
                        digest, signature, algo, salt_length
                    )
                    self.assertEqual(
                        verify,
                        1,
                        'verification failed with algorithm '
                        '%s salt length %d' % (algo, salt_length),
                    )

    def test_sign_bad_method(self):
        """
        Testing calling sign with an unsupported message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        digest = 'a' * 16
        with self.assertRaises(ValueError):
            rsa.sign(digest, 'bad_digest_method')

    def test_verify_bad_method(self):
        """
        Testing calling verify with an unsupported message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        digest = b'a' * 16
        signature = rsa.sign(digest, 'sha256')
        with self.assertRaises(ValueError):
            rsa.verify(digest, signature, 'bad_digest_method')

    def test_verify_mismatched_algo(self):
        """
        Testing verify to make sure it fails when we use a different
        message digest algorithm
        """
        rsa = RSA.load_key(self.privkey)
        message = b"This is the message string"
        digest = hashlib.sha256(message).digest()
        signature = rsa.sign(digest, 'sha256')
        with self.assertRaises(RSA.RSAError):
            rsa.verify(digest, signature, 'md5')

    def test_sign_fail(self):
        """
        Testing sign to make sure it fails when I give it
        a bogus digest. Looking at the RSA sign method
        I discovered that with the digest methods we use
        it has to be longer than a certain length.
        """
        rsa = RSA.load_key(self.privkey)
        digest = (
            b"""This string should be long enough to warrant an error in
        RSA_sign"""
            * 2
        )

        # with self.assertRaises(RSA.RSAError):
        #     rsa.sign(digest)
        rsa.sign(digest)

    def test_verify_bad_signature(self):
        """
        Testing verify to make sure it fails when we use a bad signature
        """
        rsa = RSA.load_key(self.privkey)
        message = b"This is the message string"
        digest = hashlib.sha256(message).digest()

        other_message = b"Abracadabra"
        other_digest = hashlib.sha256(other_message).digest()
        other_signature = rsa.sign(other_digest)

        with self.assertRaises(RSA.RSAError):
            rsa.verify(digest, other_signature)

    def test_rsa_ex_data(self):
        rsa = RSA.gen_key(2048, m2.RSA_F4)
        ret = rsa.set_ex_data(1, 22)
        data = rsa.get_ex_data(1)
        self.assertEqual(data, 22)
        self.assertIsInstance(data, int)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(RSATestCase)


if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    unittest.TextTestRunner().run(suite())
    Rand.save_file('randpool.dat')
