#!/usr/bin/env python

"""Unit tests for M2Crypto.SSL.

Copyright (c) 2000-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: test_ssl.py,v 1.1 2001/07/22 08:24:32 ngps Exp $'

import cStringIO, os, socket, string, sys
import tempfile, thread, time, unittest
from M2Crypto import Rand, SSL, httpslib, m2urllib

srv_host = 'localhost'
srv_port = 64000

class SSLClientTestCase(unittest.TestCase):

    def start_server(self, args):
        pid = os.fork()
        if pid == 0:
            os.execvp('openssl', args)
        else:
            time.sleep(0.1)
            return pid

    def stop_server(self, pid):
        os.kill(pid, 1)
        os.waitpid(pid, 0)

    def setUp(self):
        self.srv_host = srv_host
        self.srv_port = srv_port
        self.srv_addr = (srv_host, srv_port)
        self.srv_url = 'https://%s:%s/' % (srv_host, srv_port)

    def tearDown(self):
        global srv_port
        srv_port = srv_port - 1

    def test_server_simple(self):
        args = ['s_server', '-quiet', '-www', '-accept', str(self.srv_port)]
        pid = self.start_server(args)
        url = m2urllib.urlopen(self.srv_url)
        data = url.read()
        url.close()
        self.stop_server(pid)
        self.failIfEqual(data.find('s_server -quiet -www'), -1)

    def test_tls1_nok(self):
        args = ['s_server', '-quiet', '-www', '-no_tls1', '-accept', str(self.srv_port)]
        pid = self.start_server(args)
        ctx = SSL.Context('tlsv1')
        s = SSL.Connection(ctx)
        self.failUnlessRaises(SSL.SSLError, s.connect, self.srv_addr)
        s.close()
        self.stop_server(pid)

    def test_tls1_ok(self):
        args = ['s_server', '-quiet', '-www', '-accept', str(self.srv_port)]
        pid = self.start_server(args)
        ctx = SSL.Context('tlsv1')
        h = httpslib.HTTPSConnection(srv_host, srv_port, ssl_context=ctx)
        h.putrequest('GET', '/')
        h.endheaders()
        data = h.getresponse().read()
        h.close()
        self.stop_server(pid)
        self.failIfEqual(data.find('s_server -quiet -www'), -1)


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


