#!/usr/bin/env python

"""Demo for M2Crypto.ftpslib's FTP/TLS client.

This client interoperates with M2Crypto's Medusa-based FTP/TLS
server as well as Peter Runestig's patched-for-TLS OpenBSD FTP 
server.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

_RCS_id = '$Id: ftp_tls.py,v 1.2 2002/12/23 04:39:42 ngps Exp $'

from M2Crypto import SSL, ftpslib

def passive():
    ctx = SSL.Context('sslv23')
    f = ftpslib.FTP_TLS(ssl_ctx=ctx)
    f.set_pasv(1)
    f.connect('127.0.0.1', 9021)
    f.auth_tls()
    f.login('ftp', 'ngps@')
    f.prot_p()
    f.retrlines('LIST')
    f.quit()

def active():
    ctx = SSL.Context('sslv23')
    f = ftpslib.FTP_TLS(ssl_ctx=ctx)
    f.set_pasv(0)
    f.connect('127.0.0.1', 9021)
    f.auth_tls()
    f.login('ftp', 'ngps@')
    f.prot_p()
    f.retrlines('LIST')
    f.quit()


if __name__ == '__main__':
    passive()
    active()

