#!/usr/bin/env python

RCS_id = '$Id: alltests.py,v 1.2 2001/07/22 08:25:30 ngps Exp $'

import os, unittest

def suite():
    modules_to_test = ['test_bio_membuf',
        'test_bio_file',
        'test_bio_iobuf',
        'test_dh',
        'test_dsa',
        'test_rsa'] 
    if os.name == 'posix':
        modules_to_test.append('test_ssl')
    alltests = unittest.TestSuite()
    for module in map(__import__, modules_to_test):
        alltests.addTest(module.suite())
    return alltests

if __name__ == '__main__':
    from M2Crypto import Rand
    import sys
    Rand.load_file('randpool.dat', -1) 
    if not unittest.TextTestRunner().run(suite()).wasSuccessful():
        sys.exit(1)
    Rand.save_file('randpool.dat')

