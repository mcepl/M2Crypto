"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Connection.py,v 1.1 2000/02/23 15:35:02 ngps Exp $'

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

    def accept_ssl(self, addr):
        ret = m2.ssl_accept(self.ssl) 
        if not ret:
            raise Err.SSLError(Err.get_error_code(), addr)

    def accept(self):
        sock, addr = self.socket.accept()
        ssl = Connection(self.ctx, sock)
        ssl._setup_ssl(addr)
        ssl.accept_ssl(addr)
        return ssl, addr

    def connect(self, addr):
        self.socket.connect(addr)
        self._setup_ssl(addr)
        ret = m2.ssl_connect(self.ssl)
        if not ret:
            raise Err.SSLError(Err.get_error_code(), addr)

    def shutdown(self, how):
        m2.ssl_set_shutdown(self.ssl, how)

    def _write_bio(self, data):
        return m2.bio_write(self.sslbio, data)

    def _read_bio(self, size=4096):
        if size<=0:
            raise ValueError, 'size <= 0'
        return m2.bio_read(self.sslbio, size)

    send = write =_write_bio
    recv = read =_read_bio

    def _write_nbio(self, data):
        (n, err)=m2.ssl_write_nbio(self.ssl, data)
        if n==-1:
            if err==m2.ssl_error_zero_return:
                return 0
            elif err==m2.ssl_error_syscall:
                raise Err.SSLError(n, self.socket.getpeername())
            else:
                return -1
        else:
            if n==0:    # In non-blocking SSL, this means 'try again'.
                return -1
            else:
                return n

    def _read_nbio(self, size=4096):
        (n, blob, err)=m2.ssl_read_nbio(self.ssl, size)
        if n==-1:
            if err==m2.ssl_error_zero_return:
                return ''
            elif err in [m2.ssl_error_ssl, m2.ssl_error_syscall]:
                m2.err_print_errors_fp(sys.stderr)
                raise Err.SSLError(n, self.socket.getpeername())
            else:
                return None # XXX None is overloaded to mean 'try-again'.
        else:
            return blob

    def setblocking(self, mode):
        self.socket.setblocking(mode)
        if mode==0:
            self.recv=self.read=self._read_nbio
            self.send=self.write=self._write_nbio
        else:
            self.recv=self.read=self._read_bio
            self.send=self.write=self._write_bio

    def fileno(self):
        return self.socket.fileno()

    def get_state(self):
        return m2.ssl_get_state(self.ssl)

    def get_error(self, err):
        return SSL_error[m2.ssl_get_error(self.ssl, err)]
    
    def verify_ok(self):
        return (m2.ssl_get_verify_result(self.ssl) == m2.X509_V_OK)

    def get_verify_result(self):
        return m2.ssl_get_verify_result(self.ssl)

    def get_peer_cert(self):
        c=m2.ssl_get_peer_cert(self.ssl)
        if c is None:
            return None
        return X509.X509(c)
    
    def get_peer_cert_chain(self):
        c=m2.ssl_get_peer_cert_chain(self.ssl)
        if c is None:
            return None
        return X509.X509_Stack(c)
    
    def get_cipher(self):
        c=m2.ssl_get_current_cipher(self.ssl)
        if c is None:
            return None
        return Cipher(c)
    
    def get_ciphers(self):
        c=m2.ssl_get_ciphers(self.ssl)
        if c is None:
            return None
        return Cipher_Stack(c)

    def _makefile(self, mode='r', bufsize=1024):
        # XXX doesn't work
        socket2 = self.socket.makefile(mode, bufsize)
        sockbio = m2.bio_new_socket(socket2.fileno(), 1)
        ssl = m2.ssl_dup(self.ssl)
        m2.ssl_set_bio(ssl, sockbio, sockbio)
        sslbio = m2.bio_dup_chain(self.sslbio)
        #m2.bio_set_ssl(sslbio, ssl, 0)
        m2.bio_push(sslbio, sockbio)
        return BIO.IOBuffer(sslbio, mode, bufsize)

    def makefile(self, mode='r', bufsize=1024):
        # XXX Need some dup()'ing.
        return BIO.IOBuffer(self.sslbio, mode, bufsize)

    def getpeername(self):
        return self.socket.getpeername()


