"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Connection.py,v 1.3 2000/04/17 16:22:35 ngps Exp $'

# Python
import socket, sys

# M2Crypto
from Cipher import Cipher, Cipher_Stack
from M2Crypto import util, BIO, Err, X509, M2Crypto
m2 = M2Crypto

class Connection:
    def __init__(self, ctx, sock=None):
        self.ctx=ctx
        self.ssl=m2.ssl_new(self.ctx.ctx)
        if sock is not None:    
            self.socket=sock
        else:
            self.socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # XXX debugging
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def close(self):
        m2.ssl_shutdown(self.ssl)
        try:
            m2.bio_free(self.sslbio)
            m2.bio_free(self.sockbio)
        except AttributeError:
            pass
        self.socket.close()

    def bind(self, addr):
        self.socket.bind(addr)

    def listen(self, qlen=5):
        self.socket.listen(qlen)    

    def _check_ssl_return(self, ret):
        res = m2.ssl_get_error(self.ssl, ret)
        if res == m2.ssl_error_none:
            return 1
        elif res == m2.ssl_error_zero_return:
            return 0
        elif res in [m2.ssl_error_want_read, m2.ssl_error_want_write]:
            return -1
        elif res in [m2.ssl_error_syscall, m2.ssl_error_ssl]:
            raise Err.SSLError(Err.get_error_code(), self.socket.getpeername())

    def _setup_ssl(self, addr):
        self.addr=addr
        # Make a BIO_s_socket.
        self.sockbio=m2.bio_new_socket(self.socket.fileno(), 0)
        # Link SSL struct with the BIO_socket.
        m2.ssl_set_bio(self.ssl, self.sockbio, self.sockbio)
        # Make a BIO_f_ssl.
        self.sslbio=m2.bio_new(m2.bio_f_ssl())
        # Link BIO_f_ssl with the SSL struct.
        m2.bio_set_ssl(self.sslbio, self.ssl, 1)

    def accept_ssl(self):
        return self._check_ssl_return(m2.ssl_accept(self.ssl))

    def accept(self):
        sock, addr = self.socket.accept()
        ssl = Connection(self.ctx, sock)
        ssl._setup_ssl(addr)
        ssl.accept_ssl()
        return ssl, addr

#    def _old_connect(self, addr):
#        self.socket.connect(addr)
#        self._setup_ssl(addr)
#        ret = m2.ssl_connect(self.ssl)
#        if not ret:
#            raise Err.SSLError(Err.get_error_code(), addr)

    def connect(self, addr):
        self.socket.connect(addr)
        self._setup_ssl(addr)
        return self._check_ssl_return(m2.ssl_connect(self.ssl))

    def shutdown(self, how):
        m2.ssl_set_shutdown(self.ssl, how)

    def _write_bio(self, data):
        return m2.ssl_write(self.ssl, data)

    def _write_nbio(self, data):
        return m2.ssl_write_nbio(self.ssl, data)

    def _read_bio(self, size=4096):
        if size <= 0:
            raise ValueError, 'size <= 0'
        return m2.ssl_read(self.ssl, size)

    def _read_nbio(self, size=4096):
        if size <= 0:
            raise ValueError, 'size <= 0'
        return m2.ssl_read_nbio(self.ssl, size)

    send = write = _write_bio
    recv = read  = _read_bio

    def setblocking(self, mode):
        self.socket.setblocking(mode)
        if mode:
            self.send = self.write = self._write_nbio
            self.recv = self.read = self._read_nbio
        else:
            self.send = self.write = self._write_bio
            self.recv = self.read = self._read_bio

    def fileno(self):
        return self.socket.fileno()

    def get_state(self):
        return m2.ssl_get_state(self.ssl)

    def verify_ok(self):
        return (m2.ssl_get_verify_result(self.ssl) == m2.X509_V_OK)

    def get_verify_result(self):
        return m2.ssl_get_verify_result(self.ssl)

    def get_peer_cert(self):
        c=m2.ssl_get_peer_cert(self.ssl)
        if c is None:
            return None
        # Need to free the pointer coz OpenSSL doesn't.
        return X509.X509(c, 1)
    
    def get_peer_cert_chain(self):
        c=m2.ssl_get_peer_cert_chain(self.ssl)
        if c is None:
            return None
        # No need to free the pointer coz OpenSSL does.
        return X509.X509_Stack(c)
    
    def get_cipher(self):
        c=m2.ssl_get_current_cipher(self.ssl)
        if c is None:
            return None
        # XXX Need to free the pointer?
        return Cipher(c)
    
    def get_ciphers(self):
        c=m2.ssl_get_ciphers(self.ssl)
        if c is None:
            return None
        # XXX Need to free the pointer?
        return Cipher_Stack(c)

    def _makefile(self, mode='rw', bufsize=1024):
        # XXX Doesn't work.
        #sockbio = m2.bio_dup_chain(self.sockbio)
        ssl = m2.ssl_dup(self.ssl)
        m2.ssl_set_bio(ssl, sockbio, sockbio)
        sslbio = m2.bio_dup_chain(self.sslbio)
        m2.bio_set_ssl(sslbio, ssl, 0)
        m2.bio_push(sslbio, sockbio)
        return BIO.IOBuffer(sslbio, mode, bufsize)

    def makefile(self, mode='r', bufsize=1024):
        # XXX Need to dup().
        return BIO.IOBuffer(self.sslbio, mode, bufsize)

    def getpeername(self):
        return self.socket.getpeername()

    def set_session_id_ctx(self, id):
        ret = m2.ssl_set_session_id_context(self.ssl, id)
        if not ret:
            raise Err.SSLError(Err.get_error_code(), '')

