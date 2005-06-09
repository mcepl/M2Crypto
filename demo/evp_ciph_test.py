#!/usr/bin/env python

"""EVP Cipher demonstration.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

from M2Crypto import EVP, Rand
import array
import cStringIO

enc=1
dec=0

def cipher_filter(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()

def test_cipher(algo):
    otxt='against stupidity the gods themselves contend in vain'
    print 'testing', algo, '...',

    k=EVP.Cipher(algo, 'goethe','12345678', enc, 1, 'sha1', 'saltsalt', 5)
    pbuf=cStringIO.StringIO(otxt)
    cbuf=cStringIO.StringIO()
    ctxt=cipher_filter(k, pbuf, cbuf)
    pbuf.close()
    cbuf.close()

    j=EVP.Cipher(algo, 'goethe','12345678', dec, 1, 'sha1', 'saltsalt', 5)
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(ctxt)
    ptxt=cipher_filter(j, cbuf, pbuf)
    pbuf.close()
    cbuf.close()

    if otxt==ptxt:
        print 'ok'
    else:
        print 'not ok'

if __name__=='__main__':
    ciphers=['bf_ecb', 'bf_cbc', 'bf_cfb', 'bf_ofb',\
        #'idea_ecb', 'idea_cbc', 'idea_cfb', 'idea_ofb',\
        'cast5_ecb', 'cast5_cbc', 'cast5_cfb', 'cast5_ofb',\
        #'rc5_ecb', 'rc5_cbc', 'rc5_cfb', 'rc5_ofb',\
        'des_ecb', 'des_cbc', 'des_cfb', 'des_ofb',\
        'des_ede_ecb', 'des_ede_cbc', 'des_ede_cfb', 'des_ede_ofb',\
        'des_ede3_ecb', 'des_ede3_cbc', 'des_ede3_cfb', 'des_ede3_ofb',\
        #'aes_128_ecb', 'aes_128_cbc', 'aes_128_cfb', 'aes_128_ofb',\
        #'aes_192_ecb', 'aes_192_cbc', 'aes_192_cfb', 'aes_192_ofb',\
        #'aes_256_ecb', 'aes_256_cbc', 'aes_256_cfb', 'aes_256_ofb',\
        'rc4', 'rc2_40_cbc']
    Rand.load_file('randpool.dat', -1) 
    for i in ciphers:
        test_cipher(i)
    Rand.save_file('randpool.dat')

