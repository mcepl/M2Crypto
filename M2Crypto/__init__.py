"""M2Crypto = Python + OpenSSL + SWIG

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: __init__.py,v 1.4 2002/12/23 03:43:12 ngps Exp $'

import _m2crypto
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

_m2crypto.lib_init()


