#!/usr/bin/env python

"""Unit tests for M2Crypto.SSL.

Copyright (c) 2000-2004 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

import os, socket, string, sys, tempfile, thread, time, unittest
from M2Crypto import Rand, SSL, m2

srv_host = 'localhost'
srv_port = 64000

def verify_cb_new_function(ok, store):
    try:
        assert not ok
        err = store.get_error()
        assert err == m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY or \
               err == m2.X509_V_ERR_CERT_UNTRUSTED or \
               err == m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        app_data = m2.x509_store_ctx_get_app_data(store.ctx)
        assert app_data
    except AssertionError, e:
        # If we let exceptions propagate from here the
        # caller may see strange errors. This is cleaner.
        return 0   
    return 1

class VerifyCB:
    def __call__(self, ok, store):
        return verify_cb_new_function(ok, store)


class SSLClientTestCase(unittest.TestCase):

    def start_server(self, args):
        pid = os.fork()
        if pid == 0:
            os.execvp('openssl', args)
        else:
            time.sleep(0.5)
            return pid

    def stop_server(self, pid):
        os.kill(pid, 1)
        os.waitpid(pid, 0)

    def http_get(self, s):
        s.send('GET / HTTP/1.0\n\n') 
        resp = ''
        while 1:
            try:
                r = s.recv(4096)
                if not r:
                    break
            except SSL.SSLError: # s_server throws an 'unexpected eof'...
                break
            resp = resp + r 
        return resp

    def setUp(self):
        self.srv_host = srv_host
        self.srv_port = srv_port
        self.srv_addr = (srv_host, srv_port)
        self.srv_url = 'https://%s:%s/' % (srv_host, srv_port)
        self.args = ['s_server', '-quiet', '-www', '-accept', str(self.srv_port)]

    def tearDown(self):
        global srv_port
        srv_port = srv_port - 1

    def test_server_simple(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_tls1_nok(self):
        self.args.append('-no_tls1')
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('tlsv1')
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                self.failUnlessEqual(e[0], 'wrong version number')
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
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_sslv23_no_v2(self):
        self.args.append('-no_tls1')
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('sslv23')
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            self.failUnlessEqual(s.get_version(), 'SSLv3')
            s.close()
        finally:
            self.stop_server(pid)

    def test_sslv23_no_v2_no_service(self):
        self.args = self.args + ['-no_tls1', '-no_ssl3']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('sslv23')
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                # XXX Not totally sure if this is correct, but SSLv2 handling DID change.
                if m2.OPENSSL_VERSION_NUMBER < 0x90800F:
                    self.failUnlessEqual(e[0], 'unsupported protocol')
                else:
                    self.failUnlessEqual(e[1], 'Software caused connection abort')
            s.close()
        finally:
            self.stop_server(pid)

    def test_sslv23_weak_crypto(self):
        self.args = self.args + ['-no_tls1', '-no_ssl3']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context('sslv23', weak_crypto=1)
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            self.failUnlessEqual(s.get_version(), 'SSLv2')
            s.close()
        finally:
            self.stop_server(pid)

    def test_cipher_mismatch(self):
        self.args = self.args + ['-cipher', 'EXP-RC4-MD5']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('EXP-RC2-CBC-MD5')
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                self.failUnlessEqual(e[0], 'sslv3 alert handshake failure')
            s.close()
        finally:
            self.stop_server(pid)
        
    def test_no_such_cipher(self):
        self.args = self.args + ['-cipher', 'EXP-RC4-MD5']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('EXP-RC2-MD5')
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                self.failUnlessEqual(e[0], 'no ciphers available')
            s.close()
        finally:
            self.stop_server(pid)
        
    def test_no_weak_cipher(self):
        self.args = self.args + ['-cipher', 'EXP']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                self.failUnlessEqual(e[0], 'sslv3 alert handshake failure')
            s.close()
        finally:
            self.stop_server(pid)
        
    def test_use_weak_cipher(self):
        self.args = self.args + ['-cipher', 'EXP']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context(weak_crypto=1)
            s = SSL.Connection(ctx)
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)
        
    def test_cipher_ok(self):
        self.args = self.args + ['-cipher', 'EXP-RC4-MD5']
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            s = SSL.Connection(ctx)
            s.set_cipher_list('EXP-RC4-MD5')
            s.connect(self.srv_addr)
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)
        
    def verify_cb_new(self, ok, store):
        return verify_cb_new_function(ok, store)

    def test_verify_cb_new(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           self.verify_cb_new)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                assert 0, e
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_verify_cb_new_class(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           VerifyCB())
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                assert 0, e
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_verify_cb_new_function(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           verify_cb_new_function)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                assert 0, e
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_verify_cb_lambda(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           lambda ok, store: 1)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                assert 0, e
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def verify_cb_exception(self, ok, store):
        raise Exception, 'We should fail verification'

    def test_verify_cb_exception(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           self.verify_cb_exception)
            s = SSL.Connection(ctx)
            self.assertRaises(SSL.SSLError, s.connect, self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def test_verify_cb_not_callable(self):
        ctx = SSL.Context()
        self.assertRaises(TypeError,
                          ctx.set_verify,
                          SSL.verify_peer | SSL.verify_fail_if_no_peer_cert,
                          9,
                          1)

    def test_verify_cb_wrong_callable(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           lambda _: '')
            s = SSL.Connection(ctx)
            self.assertRaises(SSL.SSLError, s.connect, self.srv_addr)
            s.close()
        finally:
            self.stop_server(pid)

    def verify_cb_old(self, ctx_ptr, x509_ptr, err, depth, ok):
        try:
            from M2Crypto import X509
            assert not ok
            assert err == m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY or \
                   err == m2.X509_V_ERR_CERT_UNTRUSTED or \
                   err == m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
            assert m2.ssl_ctx_get_cert_store(ctx_ptr)
            assert X509.X509(x509_ptr).as_pem()
        except AssertionError:
            # If we let exceptions propagate from here the
            # caller may see strange errors. This is cleaner.
            return 0
        return 1

    def test_verify_cb_old(self):
        pid = self.start_server(self.args)
        try:
            ctx = SSL.Context()
            ctx.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 9,
                           self.verify_cb_old)
            s = SSL.Connection(ctx)
            try:
                s.connect(self.srv_addr)
            except SSL.SSLError, e:
                assert 0, e
            data = self.http_get(s)
            s.close()
        finally:
            self.stop_server(pid)
        self.failIf(string.find(data, 's_server -quiet -www') == -1)

    def test_twisted_wrapper(self):
        # Test only when twisted and ZopeInterfaces are present
        try:
            from twisted.internet.protocol import ClientFactory
            from twisted.protocols.basic import LineReceiver
            from twisted.internet import reactor
            import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
        except ImportError:
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
                assert 0, reason
        
            def clientConnectionLost(self, connector, reason):
                reactor.stop()
                
        pid = self.start_server(self.args)

        class ContextFactory:
            def getContext(self):
                return SSL.Context()

        try:
            global twisted_data
            twisted_data = ''
            
            contextFactory = ContextFactory()
            factory = EchoClientFactory()
            wrapper.connectSSL(srv_host, srv_port, factory, contextFactory)
            reactor.run() # This will block until reactor.stop() is called
        finally:
            self.stop_server(pid)
        self.failIf(string.find(twisted_data, 's_server -quiet -www') == -1)

    def test_checker(self):
        from M2Crypto.SSL import Checker
        from M2Crypto import X509

        check = Checker.Checker(host=srv_host,
                                peerCertHash='545C873E4FF7E31BF439D80C9F5F128DF7E3EE57')
        x509 = X509.load_cert('server.pem')
        assert check(x509, srv_host)
        self.assertRaises(Checker.WrongHost, check, x509, 'example.com')
        
        import doctest
        doctest.testmod(Checker)
        
    def test_ctx_load_verify_locations(self):
        ctx = SSL.Context()
        self.assertRaises(AssertionError, ctx.load_verify_locations, None, None)

twisted_data = ''

def suite():
    return unittest.makeSuite(SSLClientTestCase)
    

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
        chunk = string.split(ps)
        pid, cmd = chunk[0], chunk[4]
        if cmd == s:
            os.kill(int(pid), 1)
    f.close()
    os.unlink(fn)


if __name__ == '__main__':
    try:
        Rand.load_file('../randpool.dat', -1) 
        unittest.TextTestRunner().run(suite())
        Rand.save_file('../randpool.dat')
    finally:
        zap_servers()


"""
Client tests:
- server -verify
- server -Verify
- server -nbio
- server -nbio_test
- server -nocert
+ simple server test
+ server -cipher
+ server -tls1
+ server -no_tls1

Server tests:
- ???

Others:
- ssl_dispatcher
- SSLServer
- ForkingSSLServer
- ThreadingSSLServer
"""
