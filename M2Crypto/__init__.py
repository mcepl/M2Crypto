""" M2Crypto
Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: __init__.py,v 1.3 2000/04/17 16:18:40 ngps Exp $'

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

encrypt=1
decrypt=0

_m2crypto.lib_init()

