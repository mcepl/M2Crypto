"""BIO cipher filtering demonstration.
Copyright (c) 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: bio_ciph_test.py,v 1.1 2000/08/23 15:37:51 ngps Exp $'

from M2Crypto import BIO, Rand, m2

enc=1
dec=0

def test_py(cipher):
    data = '123456789012345678901234'
    # Encrypt.
    mem = BIO.MemoryBuffer()
    cf = BIO.CipherFilter(mem)
    cf.set_cipher(cipher, 'key', 'iv', 1)
    cf.write(data)
    cf.flush()
    cf.write_close()
    cf.close()
    xxx = mem.read()

    # Decrypt.
    mem = BIO.MemoryBuffer(xxx)
    cf = BIO.CipherFilter(mem)
    cf.set_cipher(cipher, 'key', 'iv', 0)
    cf.write_close()
    data2 = cf.read()
    cf.close()

    print '%s:%s:%s' % (cipher, data, data2)


if __name__=='__main__':
    ciphers=['bf_ecb', 'bf_cbc', 'bf_cfb', 'bf_ofb',\
        'idea_ecb', 'idea_cbc', 'idea_cfb', 'idea_ofb',\
        'cast5_ecb', 'cast5_cbc', 'cast5_cfb', 'cast5_ofb',\
        'rc5_ecb', 'rc5_cbc', 'rc5_cfb', 'rc5_ofb',\
        'des_ecb', 'des_cbc', 'des_cfb', 'des_ofb',\
        'des_ede_ecb', 'des_ede_cbc', 'des_ede_cfb', 'des_ede_ofb',\
        'des_ede3_ecb', 'des_ede3_cbc', 'des_ede3_cfb', 'des_ede3_ofb',\
        'rc4', 'rc2_40_cbc']
    Rand.load_file('randpool.dat', -1) 
    for i in ciphers:
        #test_c(i)
        test_py(i)
    Rand.save_file('randpool.dat')

