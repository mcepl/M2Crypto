#!/usr/bin/env python
from __future__ import absolute_import, print_function
"""Unit tests for M2Crypto.SSL.

Copyright (c) 2000-2004 Ng Pheng Siong. All rights reserved.

Copyright (c) 2009-2010 Heikki Toivonen. All rights reserved.
"""

"""
TODO

Server tests:
- ???

Others:
- ssl_dispatcher
- SSLServer
- ForkingSSLServer
- ThreadingSSLServer
"""
import logging
import os
import signal
import socket
import sys
import tempfile
import time
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from M2Crypto import Err, Rand, SSL, m2, util
from tests import plat_fedora
from tests.fips import fips_mode

logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    level=logging.DEBUG)
log = logging.getLogger('test_SSL')

# FIXME
# It would be probably better if the port was randomly selected.
# https://fedorahosted.org/libuser/browser/tests/alloc_port.c
srv_host = 'localhost'


def allocate_srv_port():
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((srv_host, 0))
        (host, port) = s.getsockname()
    finally:
        s.close()
    return port


def verify_cb_new_function(ok, store):
    try:
        assert not ok
        err = store.get_error()
        assert err in [m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
                       m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                       m2.X509_V_ERR_CERT_UNTRUSTED,
                       m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE]
        assert store.get_error_depth() == 0
        app_data = m2.x509_store_ctx_get_app_data(store.ctx)
        assert app_data
        x509 = store.get_current_cert()
        assert x509
        stack = store.get1_chain()
        assert len(stack) == 1
        assert stack[0].as_pem() == x509.as_pem()
    except AssertionError:
        # If we let exceptions propagate from here the
        # caller may see strange errors. This is cleaner.
        return 0
    return 1


class VerifyCB:
    def __call__(self, ok, store):
        return verify_cb_new_function(ok, store)

sleepTime = float(os.getenv('M2CRYPTO_TEST_SSL_SLEEP', 1.5))


def find_openssl():
    if os.name == 'nt' or sys.platform == 'cygwin':
        openssl = 'openssl.exe'
    else:
        openssl = 'openssl'

    plist = os.environ['PATH'].split(os.pathsep)
    for p in plist:
        try:
            dir = os.listdir(p)
            if openssl in dir:
                return True
        except:
            pass
    return False


class BaseSSLClientTestCase(unittest.TestCase):

    openssl_in_path = find_openssl()

    def start_server(self, args):
        if not self.openssl_in_path:
            raise Exception('openssl command not in PATH')

        pid = os.fork()
        if pid == 0:
            # openssl must be started in the tests directory for it
            # to find the .pem files
            os.chdir('tests')
            try:
                os.execvp('openssl', args)
            finally:
                os.chdir('..')

        else:
            time.sleep(sleepTime)
            return pid

    def stop_server(self, pid):
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)

    def http_get(self, s):
        s.send('GET / HTTP/1.0\n\n')
        resp = b''
        while 1:
            try:
                r = s.recv(4096)
                if not r:
                    break
            except SSL.SSLError:  # s_server throws an 'unexpected eof'...
                break
            resp = resp + r
        return util.py3str(resp)

    def setUp(self):
        self.srv_host = srv_host
        self.srv_port = allocate_srv_port()
        self.srv_addr = (srv_host, self.srv_port)
        self.srv_url = 'https://%s:%s/' % (srv_host, self.srv_port)
        self.args = ['s_server', '-quiet', '-www',
                     # '-cert', 'server.pem', Implicitly using this
                     '-accept', str(self.srv_port)]


class PassSSLClientTestCase(BaseSSLClientTestCase):

    def test_pass(self):
        pass


class HttpslibSSLClientTestCase(BaseSSLClientTestCase):

    def test_HTTPSConnection(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import httpslib
            c = httpslib.HTTPSConnection(srv_host, self.srv_port)
            c.request('GET', '/')
            data = c.getresponse().read()
            c.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', util.py3str(data))

    def test_HTTPSConnection_resume_session(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import httpslib
            ctx = SSL.Context()
            ctx.load_verify_locations(cafile='tests/ca.pem')
            ctx.load_cert('tests/x509.pem')
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           1)
            ctx.set_session_cache_mode(m2.SSL_SESS_CACHE_CLIENT)
            c = httpslib.HTTPSConnection(srv_host, self.srv_port,
                                         ssl_context=ctx)
            c.request('GET', '/')
            ses = c.get_session()
            t = ses.as_text()
            data = c.getresponse().read()
            # Appearently closing connection here screws session; Ali Polatel?
            # c.close()

            ctx2 = SSL.Context()
            ctx2.load_verify_locations(cafile='tests/ca.pem')
            ctx2.load_cert('tests/x509.pem')
            ctx2.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                            1)
            ctx2.set_session_cache_mode(m2.SSL_SESS_CACHE_CLIENT)
            c2 = httpslib.HTTPSConnection(srv_host, self.srv_port,
                                          ssl_context=ctx2)
            c2.set_session(ses)
            c2.request('GET', '/')
            ses2 = c2.get_session()
            t2 = ses2.as_text()
            data = c2.getresponse().read()
            c.close()
            c2.close()
            self.assertEqual(t, t2, "Sessions did not match")
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_HTTPSConnection_secure_context(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import httpslib
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            c = httpslib.HTTPSConnection(srv_host, self.srv_port,
                                         ssl_context=ctx)
            c.request('GET', '/')
            data = c.getresponse().read()
            c.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_HTTPSConnection_secure_context_fail(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import httpslib
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/server.pem')
            c = httpslib.HTTPSConnection(srv_host, self.srv_port,
                                         ssl_context=ctx)
            with self.assertRaises(SSL.SSLError):
                c.request('GET', '/')
            c.close()
        finally:
            self.stop_server(pid)

    def test_HTTPSConnection_illegalkeywordarg(self):
        from M2Crypto import httpslib
        with self.assertRaises(ValueError):
            httpslib.HTTPSConnection('example.org', badKeyword=True)


class MiscSSLClientTestCase(BaseSSLClientTestCase):

    def test_no_connection(self):
        ctx = SSL.Context()
        SSL.Connection(ctx)

    def test_server_simple(self):
        pid = self.start_server(self.args)
        try:
            with self.assertRaises(ValueError):
                SSL.Context('tlsv5')
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            with self.assertRaises(ValueError):
                s.read(0)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_server_simple_secure_context(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_server_simple_secure_context_fail(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/server.pem')
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_server_simple_timeouts(self):
        pid = self.start_server(self.args)
        try:
            with self.assertRaises(ValueError):
                SSL.Context('tlsv5')
            ctx = SSL.Context()
            s = SSL.Connection(ctx)

            r = s.get_socket_read_timeout()
            w = s.get_socket_write_timeout()
            self.assertEqual(r.sec, 0, r.sec)
            self.assertEqual(r.microsec, 0, r.microsec)
            self.assertEqual(w.sec, 0, w.sec)
            self.assertEqual(w.microsec, 0, w.microsec)

            s.set_socket_read_timeout(SSL.timeout())
            s.set_socket_write_timeout(SSL.timeout(909, 9))
            r = s.get_socket_read_timeout()
            w = s.get_socket_write_timeout()
            self.assertEqual(r.sec, 600, r.sec)
            self.assertEqual(r.microsec, 0, r.microsec)
            self.assertEqual(w.sec, 909, w.sec)
            # self.assertEqual(w.microsec, 9, w.microsec) XXX 4000

            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    # TLS is required in FIPS mode
    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    def test_tls1_nok(self):
        self.args.append('-no_tls1')
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('tlsv1')
            s = SSL.Connection(ctx)
            with self.assertRaisesRegexp(SSL.SSLError,
                                         r'wrong version number|unexpected eof'):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_tls1_ok(self):
        self.args.append('-tls1')
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('tlsv1')
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    # TLS is required in FIPS mode
    @unittest.skipIf(fips_mode, "Can't be run in FIPS mode")
    @unittest.skipUnless(hasattr(m2, "sslv2_method"),
                         "This platform doesn't support SSLv2")
    def test_sslv23_weak_crypto(self):
        self.args = self.args + ['-ssl2']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('sslv23', weak_crypto=1)
            s = SSL.Connection(ctx)
            # SSLv2 ciphers disabled by default in newer OpenSSL
            if plat_fedora and m2.OPENSSL_VERSION_NUMBER < 0x10000000:
                s.connect(self.srv_addr)
                self.assertEqual(s.get_version(), 'SSLv2')
            else:
                with self.assertRaises(SSL.SSLError):
                    s.connect(self.srv_addr)
            s.close()
        except Exception as ex:
            print(('Caught exception %s' % ex))
            raise
        finally:
            self.stop_server(pid)

    def test_cipher_mismatch(self):
        self.args = self.args + ['-cipher', 'AES256-SHA']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('AES128-SHA')
            with self.assertRaisesRegexp(SSL.SSLError,
                                         'sslv3 alert handshake failure'):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_no_such_cipher(self):
        self.args = self.args + ['-cipher', 'AES128-SHA']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('EXP-RC2-MD5')
            with self.assertRaisesRegexp(SSL.SSLError, 'no ciphers available'):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_cipher_ok(self):
        self.args = self.args + ['-cipher', 'AES128-SHA']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('AES128-SHA')
            s.connect(self.srv_addr)
            data = self.http_get(s)

            self.assertEqual(s.get_cipher().name(), 'AES128-SHA',
                             s.get_cipher().name())

            cipher_stack = s.get_ciphers()
            self.assertEqual(cipher_stack[0].name(), 'AES128-SHA',
                             cipher_stack[0].name())

            with self.assertRaises(IndexError):
                cipher_stack.__getitem__(2)

            # For some reason there are 2 entries in the stack
            # self.assertEqual(len(cipher_stack), 1, len(cipher_stack))
            self.assertEqual(s.get_cipher_list(), 'AES128-SHA',
                             s.get_cipher_list())

            # Test Cipher_Stack iterator
            i = 0
            for cipher in cipher_stack:
                i += 1
                self.assertEqual(cipher.name(), 'AES128-SHA',
                                 '"%s"' % cipher.name())
                self.assertEqual('AES128-SHA-128', str(cipher))
            # For some reason there are 2 entries in the stack
            # self.assertEqual(i, 1, i)
            self.assertEqual(i, len(cipher_stack))

            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def verify_cb_new(self, ok, store):
        return verify_cb_new_function(ok, store)

    def test_verify_cb_new(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, self.verify_cb_new)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cb_new_class(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, VerifyCB())
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cb_new_function(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, verify_cb_new_function)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cb_lambda(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, lambda ok, store: 1)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def verify_cb_exception(self, ok, store):
        self.fail('We should fail verification')

    def test_verify_cb_exception(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, self.verify_cb_exception)
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_verify_cb_not_callable(self):
        ctx = SSL.Context()
        with self.assertRaises(TypeError):
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, 1)

    def test_verify_cb_wrong_callable(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, lambda _: '')
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def verify_cb_old(self, ctx_ptr, x509_ptr, err, depth, ok):
        try:
            from M2Crypto import X509
            self.assertFalse(ok)
            self.assertIn(err,
                          [m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
                           m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                           m2.X509_V_ERR_CERT_UNTRUSTED,
                           m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE])
            self.assertTrue(m2.ssl_ctx_get_cert_store(ctx_ptr))
            self.assertTrue(X509.X509(x509_ptr).as_pem())
        except AssertionError:
            # If we let exceptions propagate from here the
            # caller may see strange errors. This is cleaner.
            return 0
        return 1

    def test_verify_cb_old(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, self.verify_cb_old)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_allow_unknown_old(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, SSL.cb.ssl_verify_callback_allow_unknown_ca)
            ctx.set_allow_unknown_ca(1)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError:
                log.error('Failed to connect to %s', self.srv_addr)
                raise
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_allow_unknown_new(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9, SSL.cb.ssl_verify_callback_allow_unknown_ca)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cert(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cert_fail(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/server.pem')
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_verify_cert_mutual_auth(self):
        self.args.extend(['-Verify', '2', '-CAfile', 'ca.pem'])
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            ctx.load_cert('tests/x509.pem')
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cert_mutual_auth_servernbio(self):
        self.args.extend(['-Verify', '2', '-CAfile', 'ca.pem', '-nbio'])
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            ctx.load_cert('tests/x509.pem')
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_verify_cert_mutual_auth_fail(self):
        self.args.extend(['-Verify', '2', '-CAfile', 'ca.pem'])
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_verify_nocert_fail(self):
        self.args.extend(['-nocert'])
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                           9)
            ctx.load_verify_locations('tests/ca.pem')
            s = SSL.Connection(ctx)
            with self.assertRaises(SSL.SSLError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_blocking0(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.setblocking(0)
            with self.assertRaises(Exception):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_blocking1(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.setblocking(1)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_makefile(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            bio = s.makefile('rwb')
            # s.close()  # XXX bug 6628?
            bio.write(b'GET / HTTP/1.0\n\n')
            bio.flush()
            data = bio.read()
            bio.close()
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_makefile_err(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError as e:
                self.fail(e)
            f = s.makefile()
            data = self.http_get(s)
            s.close()
            del f
            del s
            err_code = Err.peek_error_code()
            self.assertEqual(err_code, 0,
                             'Unexpected error: %s' % err_code)
            err = Err.get_error()
            self.assertIsNone(err, 'Unexpected error: %s' % err)
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_info_callback(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_info_callback()
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)


class UrllibSSLClientTestCase(BaseSSLClientTestCase):

    def test_urllib(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import m2urllib
            url = m2urllib.FancyURLopener()
            url.addheader('Connection', 'close')
            u = url.open('https://%s:%s/' % (srv_host, self.srv_port))
            data = u.read()
            u.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    # XXX Don't actually know how to use m2urllib safely!
    # def test_urllib_safe_context(self):
    # def test_urllib_safe_context_fail(self):


class Urllib2SSLClientTestCase(BaseSSLClientTestCase):

    def test_urllib2(self):
        pid = self.start_server(self.args)
        try:
            from M2Crypto import m2urllib2
            opener = m2urllib2.build_opener()
            opener.addheaders = [('Connection', 'close')]
            u = opener.open('https://%s:%s/' % (srv_host, self.srv_port))
            data = u.read()
            u.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_urllib2_secure_context(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(
                SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
            ctx.load_verify_locations('tests/ca.pem')

            from M2Crypto import m2urllib2
            opener = m2urllib2.build_opener(ctx)
            opener.addheaders = [('Connection', 'close')]
            u = opener.open('https://%s:%s/' % (srv_host, self.srv_port))
            data = u.read()
            u.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_urllib2_secure_context_fail(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(
                SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9)
            ctx.load_verify_locations('tests/server.pem')

            from M2Crypto import m2urllib2
            opener = m2urllib2.build_opener(ctx)
            opener.addheaders = [('Connection', 'close')]
            with self.assertRaises(SSL.SSLError):
                opener.open('https://%s:%s/' % (srv_host, self.srv_port))
        finally:
            self.stop_server(pid)

    def test_z_urllib2_opener(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()

            from M2Crypto import m2urllib2
            opener = m2urllib2.build_opener(
                ctx, m2urllib2.HTTPBasicAuthHandler())
            m2urllib2.install_opener(opener)
            req = m2urllib2.Request('https://%s:%s/' %
                                    (srv_host, self.srv_port))
            u = m2urllib2.urlopen(req)
            data = u.read()
            u.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_urllib2_opener_handlers(self):
        ctx = SSL.Context()

        from M2Crypto import m2urllib2
        m2urllib2.build_opener(ctx, m2urllib2.HTTPBasicAuthHandler())

    def test_urllib2_leak(self):
        pid = self.start_server(self.args)
        try:
            import gc
            from M2Crypto import m2urllib2
            o = m2urllib2.build_opener()
            r = o.open('https://%s:%s/' % (srv_host, self.srv_port))
            s = [r.fp._sock.fp]
            r.close()
            self.assertEqual(len(gc.get_referrers(s[0])), 1)
        finally:
            self.stop_server(pid)

@unittest.skipIf(not util.py27plus,
                 "Twisted doesn't test well with Python 2.6")
class TwistedSSLClientTestCase(BaseSSLClientTestCase):

    def test_timeout(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            # Just a really small number so we can timeout
            s.settimeout(0.000000000000000000000000000001)
            with self.assertRaises(SSL.SSLTimeoutError):
                s.connect(self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_makefile_timeout(self):
        # httpslib uses makefile to read the response
        pid = self.start_server(self.args)
        try:
            from M2Crypto import httpslib
            c = httpslib.HTTPSConnection(srv_host, self.srv_port)
            c.putrequest('GET', '/')
            c.putheader('Accept', 'text/html')
            c.putheader('Accept', 'text/plain')
            c.endheaders()
            c.sock.settimeout(100)
            resp = c.getresponse()
            self.assertEqual(resp.status, 200, resp.reason)
            data = resp.read()
            c.close()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', data)

    def test_makefile_timeout_fires(self):
        # This is convoluted because (openssl s_server -www) starts
        # writing the response as soon as it receives the first line of
        # the request, so it's possible for it to send the response
        # before the request is sent and there would be no timeout.  So,
        # let the server spend time reading from an empty pipe
        FIFO_NAME = 'test_makefile_timeout_fires_fifo'  # noqa
        os.mkfifo('tests/' + FIFO_NAME)
        pipe_pid = os.fork()
        try:
            if pipe_pid == 0:
                try:
                    f = open('tests/' + FIFO_NAME, 'w')
                    try:
                        time.sleep(sleepTime + 1)
                        f.write('Content\n')
                    finally:
                        f.close()
                finally:
                    os._exit(0)
            self.args[self.args.index('-www')] = '-WWW'
            pid = self.start_server(self.args)
            try:
                from M2Crypto import httpslib
                c = httpslib.HTTPSConnection(srv_host, self.srv_port)
                c.putrequest('GET', '/' + FIFO_NAME)
                c.putheader('Accept', 'text/html')
                c.putheader('Accept', 'text/plain')
                c.endheaders()
                c.sock.settimeout(0.0000000001)
                with self.assertRaises(socket.timeout):
                    c.getresponse()
                c.close()
            finally:
                self.stop_server(pid)
        finally:
            os.kill(pipe_pid, signal.SIGTERM)
            os.waitpid(pipe_pid, 0)
            os.unlink('tests/' + FIFO_NAME)

    def test_twisted_wrapper(self):
        # Test only when twisted and ZopeInterfaces are present
        try:
            from twisted.internet.protocol import ClientFactory
            from twisted.protocols.basic import LineReceiver
            from twisted.internet import reactor
            import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
        except ImportError:
            import warnings
            warnings.warn(
                'Skipping twisted wrapper test because twisted not found')
            return

        class EchoClient(LineReceiver):
            def connectionMade(self):
                self.sendLine('GET / HTTP/1.0\n\n')

            def lineReceived(self, line):
                global twisted_data
                twisted_data += line

        class EchoClientFactory(ClientFactory):
            protocol = EchoClient

            def clientConnectionFailed(self, connector, reason):
                reactor.stop()
                self.fail(reason)

            def clientConnectionLost(self, connector, reason):
                reactor.stop()

        pid = self.start_server(self.args)

        class ContextFactory:
            def getContext(self):
                return SSL.Context()

        try:
            global twisted_data
            twisted_data = ''

            context_factory = ContextFactory()
            factory = EchoClientFactory()
            wrapper.connectSSL(srv_host, self.srv_port, factory,
                               context_factory)
            # This will block until reactor.stop() is called
            reactor.run()
        finally:
            self.stop_server(pid)
        self.assertIn('s_server -quiet -www', twisted_data)


twisted_data = ''


class XmlRpcLibTestCase(unittest.TestCase):
    def test_lib(self):
        from M2Crypto import m2xmlrpclib
        m2xmlrpclib.SSL_Transport()
        # XXX need server to test against


class FtpsLibTestCase(unittest.TestCase):
    def test_lib(self):
        from M2Crypto import ftpslib
        ftpslib.FTP_TLS()
        # XXX need server to test against


class SessionTestCase(unittest.TestCase):
    def test_session_load_bad(self):
        with self.assertRaises(SSL.SSLError):
            SSL.Session.load_session('tests/signer.pem')


class FtpslibTestCase(unittest.TestCase):
    def test_26_compat(self):
        from M2Crypto import ftpslib
        f = ftpslib.FTP_TLS()
        # 2.6 used to raise AttributeError:
        with self.assertRaises(socket.gaierror):
            f.connect('no-such-host-dfgHJK56789', 990)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SessionTestCase))
    suite.addTest(unittest.makeSuite(XmlRpcLibTestCase))
    suite.addTest(unittest.makeSuite(FtpsLibTestCase))
    suite.addTest(unittest.makeSuite(PassSSLClientTestCase))
    suite.addTest(unittest.makeSuite(HttpslibSSLClientTestCase))
    suite.addTest(unittest.makeSuite(UrllibSSLClientTestCase))
    suite.addTest(unittest.makeSuite(Urllib2SSLClientTestCase))
    suite.addTest(unittest.makeSuite(MiscSSLClientTestCase))
    suite.addTest(unittest.makeSuite(FtpslibTestCase))
    try:
        if util.py27plus:
            import M2Crypto.SSL.TwistedProtocolWrapper as wrapper  # noqa
            suite.addTest(unittest.makeSuite(TwistedSSLClientTestCase))
    except ImportError:
        pass
    return suite


def zap_servers():
    s = 's_server'
    fn = tempfile.mktemp()
    cmd = 'ps | egrep %s > %s' % (s, fn)
    os.system(cmd)
    f = open(fn)
    while 1:
        ps = f.readline()
        if not ps:
            break
        chunk = ps.split()
        pid, cmd = chunk[0], chunk[4]
        if cmd == s:
            os.kill(int(pid), signal.SIGTERM)
    f.close()
    os.unlink(fn)


if __name__ == '__main__':
    report_leaks = 0

    if report_leaks:
        import gc
        gc.enable()
        gc.set_debug(gc.DEBUG_LEAK & ~gc.DEBUG_SAVEALL)

    try:
        Rand.load_file('randpool.dat', -1)
        unittest.TextTestRunner().run(suite())
        Rand.save_file('randpool.dat')
    finally:
        zap_servers()

    if report_leaks:
        from tests import alltests
        alltests.dump_garbage()
