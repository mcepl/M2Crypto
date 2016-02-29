from __future__ import absolute_import

"""M2Crypto SSL services.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

import socket

# M2Crypto
from M2Crypto import m2

class SSLError(Exception):
    pass

class SSLTimeoutError(SSLError, socket.timeout):
    pass

m2.ssl_init(SSLError, SSLTimeoutError)

# M2Crypto.SSL
from M2Crypto.SSL.Cipher import Cipher, Cipher_Stack
from M2Crypto.SSL.Connection import Connection
from M2Crypto.SSL.Context import Context
from M2Crypto.SSL.SSLServer import (ForkingSSLServer, SSLServer,
                                    ThreadingSSLServer)
from M2Crypto.SSL.ssl_dispatcher import ssl_dispatcher
from M2Crypto.SSL.timeout import timeout

verify_none = m2.SSL_VERIFY_NONE
verify_peer = m2.SSL_VERIFY_PEER
verify_fail_if_no_peer_cert = m2.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
verify_client_once = m2.SSL_VERIFY_CLIENT_ONCE

SSL_SENT_SHUTDOWN = m2.SSL_SENT_SHUTDOWN
SSL_RECEIVED_SHUTDOWN = m2.SSL_RECEIVED_SHUTDOWN

op_all = m2.SSL_OP_ALL
op_no_sslv2 = m2.SSL_OP_NO_SSLv2
