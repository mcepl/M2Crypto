"""M2Crypto client-side FTP/TLS.

This implementation complies with draft-murray-auth-ftp-ssl-07.txt.

Copyright (c) 1999-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: ftpslib.py,v 1.1 2001/09/17 14:40:53 ngps Exp $'

# Python
from ftplib import *
from ftplib import parse150, parse227
from ftplib import error_reply, error_temp, error_perm, error_proto
import socket

# M2Crypto
import SSL

DEFAULT_PROTOCOL='sslv23'

class FTP_TLS(FTP):

    """An FTP/TLS client."""

    def __init__(self, host=None, ssl_ctx=None):
        """Initialise the client. If 'host' is supplied, connect to it."""
        if ssl_ctx is not None:
            self.ssl_ctx = ssl_ctx
        else:
            self.ssl_ctx = SSL.Context(DEFAULT_PROTOCOL)
        if host:
            self.connect(host)
        self.prot = 0

    def auth_tls(self):
        """Initiate a secure connection per AUTH TLS, aka AUTH TLS-C."""
        self.voidcmd('AUTH TLS')
        s = SSL.Connection(self.ssl_ctx, self.sock)
        s.setup_ssl()
        s.set_connect_state()
        # We're in blocking mode, meaning the following connect_ssl() 
        # either succeeds or throws an SSL.SSLError.
        s.connect_ssl()
        self.sock = s
        self.file = self.sock.makefile()

    def auth_ssl(self):
        """Initiate a secure connection per AUTH SSL, aka AUTH TLS-P."""
        raise NotImplementedError

    def pbsz(self):
        """Send PBSZ for secure data connection."""
        self.voidcmd('PBSZ 0')

    def prot_p(self):
        """Send PROT P for secure data connection."""
        self.voidcmd('PROT P')
        self.prot = 1
            
    def prot_c(self):
        """Send PROT C for data connection in the clear."""
        self.voidcmd('PROT C')
        self.prot = 0
            
    def ntransfercmd(self, cmd, rest=None):
        """Initiate a transfer over a clear or secure connection."""
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self.prot:
            conn = SSL.Connection(self.ssl_ctx, conn)
            conn.setup_ssl()
            if self.passiveserver:
                conn.set_connect_state()
                conn.connect_ssl()
            else:
                conn.set_accept_state()
                conn.accept_ssl()
        return conn, size
        

