""" M2Crypto
Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: __init__.py,v 1.2 1999/09/12 14:32:21 ngps Exp $'

import sys

import _m2crypto
import BIO
import Rand
import DH
import DSA
import RSA
import RC4
import SSL
import X509

encrypt=1
decrypt=0

_m2crypto.lib_init()

