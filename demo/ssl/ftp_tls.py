#!/usr/bin/env python

"""Demo for M2Crypto.ftpslib's FTP/TLS client.

This client interoperates with M2Crypto's Medusa-based FTP/TLS
server as well as Peter Runestig's patched-for-TLS OpenBSD FTP 
server.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

_RCS_id = '$Id: ftp_tls.py,v 1.3 2003/06/22 17:16:40 ngps Exp $'

from M2Crypto import SSL, ftpslib, threading

def passive():
    ctx = SSL.Context('sslv23')
    f = ftpslib.FTP_TLS(ssl_ctx=ctx)
    f.connect('127.0.0.1', 9021)
    f.auth_tls()
    f.set_pasv(1)    
    f.login('ftp', 'ngps@')
    f.prot_p()
    f.retrlines('LIST')
    f.quit()

def active():
    ctx = SSL.Context('sslv23')
    f = ftpslib.FTP_TLS(ssl_ctx=ctx)
    f.connect('127.0.0.1', 9021)
    f.auth_tls()
    f.set_pasv(0)
    f.login('ftp', 'ngps@')
    f.prot_p()
    f.retrlines('LIST')
    f.quit()


if __name__ == '__main__':
    threading.init()
    active()
    passive()
    threading.cleanup()

