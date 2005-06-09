"""BIO cipher filtering demonstration.
Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

from M2Crypto import BIO, Rand, m2

enc=1
dec=0

def test_py(cipher):
    data = '123456789012345678901234'
    # Encrypt.
    mem = BIO.MemoryBuffer()
    cf = BIO.CipherStream(mem)
    cf.set_cipher(cipher, 'key', 'iv', 1)
    cf.write(data)
    cf.flush()
    cf.write_close()
    cf.close()
    xxx = mem.read()

    # Decrypt.
    mem = BIO.MemoryBuffer(xxx)
    cf = BIO.CipherStream(mem)
    cf.set_cipher(cipher, 'key', 'iv', 0)
    cf.write_close()
    data2 = cf.read()
    cf.close()

    print '%s:%s:%s' % (cipher, data, data2)


if __name__=='__main__':
    ciphers=['bf_ecb', 'bf_cbc', 'bf_cfb', 'bf_ofb',\
        #'idea_ecb', 'idea_cbc', 'idea_cfb', 'idea_ofb',\
        'cast5_ecb', 'cast5_cbc', 'cast5_cfb', 'cast5_ofb',\
        #'rc5_ecb', 'rc5_cbc', 'rc5_cfb', 'rc5_ofb',\
        'des_ecb', 'des_cbc', 'des_cfb', 'des_ofb',\
        'des_ede_ecb', 'des_ede_cbc', 'des_ede_cfb', 'des_ede_ofb',\
        'des_ede3_ecb', 'des_ede3_cbc', 'des_ede3_cfb', 'des_ede3_ofb',\
        'aes_128_ecb', 'aes_128_cbc', 'aes_128_cfb', 'aes_128_ofb',\
        'aes_192_ecb', 'aes_192_cbc', 'aes_192_cfb', 'aes_192_ofb',\
        'aes_256_ecb', 'aes_256_cbc', 'aes_256_cfb', 'aes_256_ofb',\
        'rc4', 'rc2_40_cbc']
    Rand.load_file('randpool.dat', -1) 
    for i in ciphers:
        test_py(i)
    Rand.save_file('randpool.dat')

