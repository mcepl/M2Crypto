"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: __init__.py,v 1.1 2000/02/23 15:37:43 ngps Exp $'

# M2Crypto.SSL
from Cipher import Cipher, Cipher_Stack
from Context import Context
from Connection import Connection
from SSLServer import SSLServer, ForkingSSLServer, ThreadingSSLServer
from ssl_dispatcher import ssl_dispatcher

# M2Crypto
from M2Crypto import M2Crypto
m2 = M2Crypto

m2.ssl_init()

verify_none = m2.SSL_VERIFY_NONE
verify_peer = m2.SSL_VERIFY_PEER
verify_fail_if_no_peer_cert = m2.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
verify_client_once = m2.SSL_VERIFY_CLIENT_ONCE

