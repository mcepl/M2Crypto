#!/usr/bin/env python

"""X.509 certificate manipulation and such.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: demo1.py,v 1.1 1999/12/22 15:45:53 ngps Exp $'

import os

from M2Crypto import X509
from M2Crypto.EVP import MessageDigest

def demo1():
    print 'Test 1: As DER...'
    cert1 = X509.load_cert('ca.pem')
    der1 = cert1.as_der()
    dgst1 = MessageDigest('sha1')
    dgst1.update(der1)
    print 'Using M2Crypto:\n', `dgst1.final()`, '\n'

    cert2 = os.popen('openssl x509 -inform pem -outform der -in ca.pem')
    der2 = cert2.read()
    dgst2 = MessageDigest('sha1')
    dgst2.update(der2)
    print 'Openssl command line:\n', `dgst2.final()`, '\n'


def demo2():
    print 'Test 2: As text...'
    cert = X509.load_cert('ca.pem')
    print cert.as_text(), '\n'


if __name__ == "__main__":
    demo1()
    demo2()
