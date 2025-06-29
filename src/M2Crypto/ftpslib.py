"""M2Crypto client-side FTP/TLS.

This implementation complies with draft-murray-auth-ftp-ssl-07.txt.

Example:

    from M2Crypto import ftpslib
    f = ftpslib.FTP_TLS()
    f.connect('ftp.example.com', 21)
    f.auth_tls()
    f.set_pasv(0)
    f.login('username', 'password')
    f.retrlines('LIST')
    # Output:
    # -rw-rw-r--   1 0        198          2326 Jul  3  1996 apache_pb.gif
    # drwxrwxr-x   7 0        198          1536 Oct 10  2000 manual
    # drwxrwxr-x   2 0        198           512 Oct 31  2000 modpy
    # drwxrwxr-x   2 0        198           512 Oct 31  2000 bobo
    # ...
    # '226 Transfer complete'
    f.quit()
    # '221 Goodbye.'

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

# We want to import whole stdlib ftplib objects, because our users want
# to use them.
from ftplib import *  # noqa

# M2Crypto
from M2Crypto import SSL


class FTP_TLS(FTP):
    """Python OO interface to client-side FTP/TLS."""

    def __init__(self, host=None, ssl_ctx=None):
        """Initialise the client. If 'host' is supplied, connect to it."""
        if ssl_ctx is not None:
            self.ssl_ctx = ssl_ctx
        else:
            self.ssl_ctx = SSL.Context()
        FTP.__init__(self, host)
        self.prot = 0

    def auth_tls(self):
        """Secure the control connection per AUTH TLS, aka AUTH TLS-C."""
        self.voidcmd('AUTH TLS')
        s = SSL.Connection(self.ssl_ctx, self.sock)
        s.setup_ssl()
        s.set_connect_state()
        s.connect_ssl()
        self.sock = s
        self.file = self.sock.makefile()

    def auth_ssl(self):
        """Secure the control connection per AUTH SSL, aka AUTH TLS-P."""
        raise NotImplementedError

    def prot_p(self):
        """Set up secure data connection."""
        self.voidcmd('PBSZ 0')
        self.voidcmd('PROT P')
        self.prot = 1

    def prot_c(self):
        """Set up data connection in the clear."""
        self.voidcmd('PROT C')
        self.prot = 0

    def ntransfercmd(self, cmd, rest=None):
        """Initiate a data transfer."""
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self.prot:
            conn = SSL.Connection(self.ssl_ctx, conn)
            conn.setup_ssl()
            conn.set_connect_state()
            conn.set_session(self.sock.get_session())
            conn.connect_ssl()
        return conn, size
