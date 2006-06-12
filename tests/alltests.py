#!/usr/bin/env python

def suite():
    from M2Crypto import m2
    
    modules_to_test = [
        'test_asn1',
        'test_bio',
        'test_bio_membuf',
        'test_bio_file',
        'test_bio_iobuf',
        'test_bio_ssl',
        'test_bn',
        'test_authcookie',
        'test_dh',
        'test_dsa',
        'test_evp',
        'test_rsa',
        'test_smime',
        'test_x509']
    if os.name == 'posix':
        modules_to_test.append('test_ssl')
    elif os.name == 'nt':
        modules_to_test.append('test_ssl_win')
    if m2.OPENSSL_VERSION_NUMBER >= 0x90800F and m2.OPENSSL_NO_EC == 0:
        modules_to_test.append('test_ecdh')
        modules_to_test.append('test_ecdsa')
    alltests = unittest.TestSuite()
    for module in map(__import__, modules_to_test):
        alltests.addTest(module.suite())
    return alltests


def dump_garbage():
    import gc
    print '\nGarbage:'
    gc.collect()
    if len(gc.garbage):
    
        print '\nLeaked objects:'
        for x in gc.garbage:
            s = str(x)
            if len(s) > 77: s = s[:73]+'...'
            print type(x), '\n  ', s
    
        print 'There were %d leaks.' % len(gc.garbage)
    else:
        print 'Python garabge collector did not detect any leaks.'
        print 'However, it is still possible there are leaks in the C code.'


if __name__ == '__main__':
    report_leaks = 0
    
    if report_leaks:
        import gc
        gc.enable()
        gc.set_debug(gc.DEBUG_LEAK & ~gc.DEBUG_SAVEALL)
    
    import os, unittest
    from M2Crypto import Rand
    
    try:
        Rand.load_file('randpool.dat', -1) 
        unittest.TextTestRunner().run(suite())
        Rand.save_file('randpool.dat')
    finally:
        if os.name == 'posix':
            from test_ssl import zap_servers
            zap_servers()

    if report_leaks:
        dump_garbage()
