#!/usr/bin/env python

RCS_id = '$Id$'

import os, unittest
from M2Crypto import Rand

def suite():
    modules_to_test = [
        'test_asn1',
        'test_bio_membuf',
        'test_bio_file',
        'test_bio_iobuf',
        'test_bn',
        'test_authcookie',
        'test_dh',
        'test_dsa',
        'test_evp',
        'test_rsa',
        'test_x509']
    if os.name == 'posix':
        modules_to_test.append('test_ssl')
    elif os.name == 'nt':
        modules_to_test.append('test_ssl_win')
    alltests = unittest.TestSuite()
    for module in map(__import__, modules_to_test):
        alltests.addTest(module.suite())
    return alltests

if __name__ == '__main__':
    try:
        Rand.load_file('randpool.dat', -1) 
        unittest.TextTestRunner().run(suite())
        Rand.save_file('randpool.dat')
    finally:
        if os.name == 'posix':
            from test_ssl import zap_servers
            zap_servers()


