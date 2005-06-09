"""M2Crypto.SSL.Connection

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

RCS_id = '$Id$'

# Python
import socket

# M2Crypto
from Cipher import Cipher, Cipher_Stack
from Session import Session
from M2Crypto import BIO, X509, m2
import timeout
import Checker

#SSLError = getattr(__import__('M2Crypto.SSL', globals(), locals(), 'SSLError'), 'SSLError')
from M2Crypto.SSL import SSLError

def _serverPostConnectionCheck(peerX509, expectedHost):
    return 1

class Connection:

    """An SSL connection."""

    clientPostConnectionCheck = Checker.Checker()
    serverPostConnectionCheck = _serverPostConnectionCheck

    def __init__(self, ctx, sock=None):
        self.ctx = ctx
        self.ssl = m2.ssl_new(self.ctx.ctx)
        if sock is not None:    
            self.socket = sock
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._fileno = self.socket.fileno()

    def __del__(self):
        try:
            m2.bio_free(self.sslbio)
            m2.bio_free(self.sockbio)
        except AttributeError:
            pass
        self.socket.close()

    def close(self):
        m2.ssl_shutdown(self.ssl)

    def clear(self):
        """
        If there were errors in this connection, call clear() rather
        than close() to end it, so that bad sessions will be cleared
        from cache.
        """
        return m2.ssl_clear(self.ssl)

    def set_shutdown(self, mode):
        m2.ssl_set_shutdown1(self.ssl, mode)

    def get_shutdown(self):
        return m2.ssl_get_shutdown(self.ssl)

    def bind(self, addr):
        self.socket.bind(addr)

    def listen(self, qlen=5):
        self.socket.listen(qlen)    

    def ssl_get_error(self, ret):
        return m2.ssl_get_error(self.ssl, ret)

    def set_client_CA_list_from_file(self, cafile):
        m2.ssl_set_client_CA_list(self.ssl, cafile)

    def set_client_CA_list_from_context(self):
        m2.ssl_set_client_CA_list_from_context(self.ssl, self.ctx.ctx)

    def setup_addr(self, addr):
        self.addr = addr

    def setup_ssl(self):
        # Make a BIO_s_socket.
        self.sockbio = m2.bio_new_socket(self.socket.fileno(), 0)
        # Link SSL struct with the BIO_socket.
        m2.ssl_set_bio(self.ssl, self.sockbio, self.sockbio)
        # Make a BIO_f_ssl.
        self.sslbio = m2.bio_new(m2.bio_f_ssl())
        # Link BIO_f_ssl with the SSL struct.
        m2.bio_set_ssl(self.sslbio, self.ssl, 1)

    def _setup_ssl(self, addr):
        """Deprecated"""
        self.setup_addr(addr)
        self.setup_ssl()

    def set_accept_state(self):
        m2.ssl_set_accept_state(self.ssl)

    def accept_ssl(self):
        return m2.ssl_accept(self.ssl)

    def accept(self):
        """Accept an SSL connection. The return value is a pair (ssl, addr) where
        ssl is a new SSL connection object and addr is the address bound to the
        the other end of the SSL connection."""
        sock, addr = self.socket.accept()
        ssl = Connection(self.ctx, sock)
        ssl.addr = addr
        ssl.setup_ssl()
        ssl.set_accept_state()
        ssl.accept_ssl()
        check = getattr(self, 'postConnectionCheck', Connection.serverPostConnectionCheck)
        if check is not None:
            if not check(self.get_peer_cert(), self.addr[0]):
                raise Checker.SSLVerificationError, 'post connection check failed'
        return ssl, addr

    def set_connect_state(self):
        m2.ssl_set_connect_state(self.ssl)

    def connect_ssl(self):
        return m2.ssl_connect(self.ssl)

    def connect(self, addr):
        self.socket.connect(addr)
        self.addr = addr
        self.setup_ssl()
        self.set_connect_state()
        ret = self.connect_ssl()
        check = getattr(self, 'postConnectionCheck', Connection.clientPostConnectionCheck)
        if check is not None:
            if not check(self.get_peer_cert(), self.addr[0]):
                raise Checker.SSLVerificationError, 'post connection check failed'
        return ret

    def shutdown(self, how):
        m2.ssl_set_shutdown(self.ssl, how)

    def renegotiate(self):
        """Renegotiate this connection's SSL parameters."""
        return m2.ssl_renegotiate(self.ssl)

    def pending(self):
        """Return the numbers of octets that can be read from the 
        connection."""
        return m2.ssl_pending(self.ssl)

    def _write_bio(self, data):
        return m2.ssl_write(self.ssl, data)

    def _write_nbio(self, data):
        return m2.ssl_write_nbio(self.ssl, data)

    def _read_bio(self, size=1024):
        if size <= 0:
            raise ValueError, 'size <= 0'
        return m2.ssl_read(self.ssl, size)

    def _read_nbio(self, size=1024):
        if size <= 0:
            raise ValueError, 'size <= 0'
        return m2.ssl_read_nbio(self.ssl, size)

    sendall = send = write = _write_bio
    recv = read  = _read_bio

    def setblocking(self, mode):
        """Set this connection's underlying socket to _mode_."""
        self.socket.setblocking(mode)
        if mode:
            self.send = self.write = self._write_bio
            self.recv = self.read = self._read_bio
        else:
            self.send = self.write = self._write_nbio
            self.recv = self.read = self._read_nbio

    def fileno(self):
        return self.socket.fileno()

    def getsockopt(self, *args):
        return apply(self.socket.getsockopt, args)

    def setsockopt(self, *args):
        return apply(self.socket.setsockopt, args)

    def get_context(self):
        """Return the SSL.Context object associated with this 
        connection."""
        return m2.ssl_get_ssl_ctx(self.ssl)

    def get_state(self):
        """Return the SSL state of this connection."""
        return m2.ssl_get_state(self.ssl)

    def verify_ok(self):
        return (m2.ssl_get_verify_result(self.ssl) == m2.X509_V_OK)

    def get_verify_mode(self):
        """Return the peer certificate verification mode."""
        return m2.ssl_get_verify_mode(self.ssl)

    def get_verify_depth(self):
        """Return the peer certificate verification depth."""
        return m2.ssl_get_verify_depth(self.ssl)

    def get_verify_result(self):
        """Return the peer certificate verification result."""
        return m2.ssl_get_verify_result(self.ssl)

    def get_peer_cert(self):
        """Return the peer certificate; if the peer did not provide 
        a certificate, return None."""
        c=m2.ssl_get_peer_cert(self.ssl)
        if c is None:
            return None
        # Need to free the pointer coz OpenSSL doesn't.
        return X509.X509(c, 1)
    
    def get_peer_cert_chain(self):
        """Return the peer certificate chain; if the peer did not provide 
        a certificate chain, return None."""
        c=m2.ssl_get_peer_cert_chain(self.ssl)
        if c is None:
            return None
        # No need to free the pointer coz OpenSSL does.
        return X509.X509_Stack(c)
    
    def get_cipher(self):
        """Return an M2Crypto.SSL.Cipher object for this connection; if the 
        connection has not been initialised with a cipher suite, return None."""
        c=m2.ssl_get_current_cipher(self.ssl)
        if c is None:
            return None
        # XXX Need to free the pointer?
        return Cipher(c)
    
    def get_ciphers(self):
        """Return an M2Crypto.SSL.Cipher_Stack object for this connection; if the
        connection has not been initialised with cipher suites, return None."""
        c=m2.ssl_get_ciphers(self.ssl)
        if c is None:
            return None
        # XXX Need to free the pointer?
        return Cipher_Stack(c)

    def get_cipher_list(self, idx=0):
        """Return the cipher suites for this connection as a string object."""
        return m2.ssl_get_cipher_list(self.ssl, idx)

    def set_cipher_list(self, cipher_list):
        """Set the cipher suites for this connection."""
        return m2.ssl_set_cipher_list(self.ssl, cipher_list)

    def makefile(self, mode='rb', bufsize='ignored'):
        r = 'r' in mode or '+' in mode
        w = 'w' in mode or 'a' in mode or '+' in mode
        b = 'b' in mode
        m2mode = ['', 'r'][r] + ['', 'w'][w] + ['', 'b'][b]      
        # XXX Need to dup().
        bio = BIO.BIO(self.sslbio, _close_cb=self.close)
        BIO.bio_do_ssl_handshake(bio._ptr())
        return BIO.IOBuffer(bio, m2mode)

    def getsockname(self):
        return self.socket.getsockname()

    def getpeername(self):
        return self.socket.getpeername()

    def set_session_id_ctx(self, id):
        ret = m2.ssl_set_session_id_context(self.ssl, id)
        if not ret:
            raise SSLError(m2.err_reason_error_string(m2.err_get_error()))

    def get_session(self):
        sess = m2.ssl_get_session(self.ssl)
        return Session(sess)

    def set_session(self, session):
        m2.ssl_set_session(self.ssl, session._ptr())

    def get_default_session_timeout(self):
        return m2.ssl_get_default_session_timeout(self.ssl)

    def get_socket_read_timeout(self):
        return timeout.struct_to_timeout(self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, 8))

    def get_socket_write_timeout(self):
        return timeout.struct_to_timeout(self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, 8))

    def set_socket_read_timeout(self, timeo):
        assert isinstance(timeo, timeout.timeout)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeo.pack())

    def set_socket_write_timeout(self, timeo):
        assert isinstance(timeo, timeout.timeout)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeo.pack())

    def get_version(self):
        "Return the TLS/SSL protocol version for this connection."
        return m2.ssl_get_version(self.ssl)

    def set_post_connection_check_callback(self, postConnectionCheck):
        self.postConnectionCheck = postConnectionCheck
