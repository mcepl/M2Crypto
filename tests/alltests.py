#!/usr/bin/env python2.0

RCS_id = '$Id: alltests.py,v 1.1 2000/11/08 14:39:45 ngps Exp $'

import unittest

def suite():
    modules_to_test = ('test_bio_membuf',
        'test_bio_file',
        'test_bio_iobuf') 
    alltests = unittest.TestSuite()
    for module in map(__import__, modules_to_test):
        alltests.addTest(module.suite())
    return alltests

if __name__ == '__main__':
    import sys
    if not unittest.TextTestRunner().run(suite()).wasSuccessful():
        sys.exit(1)

