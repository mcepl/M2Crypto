"""M2Crypto = Python + OpenSSL + SWIG

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: __init__.py,v 1.5 2002/12/29 12:44:33 ngps Exp $'

import __m2crypto
import BIO
import Rand
import DH
import DSA
import EVP
import RSA
import RC4
import SSL
import X509
import PGP
import m2urllib

# Backwards compatibility.
urllib2 = m2urllib

encrypt=1
decrypt=0

__m2crypto.lib_init()


