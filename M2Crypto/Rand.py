"""M2Crypto wrapper for OpenSSL PRNG. Requires OpenSSL 0.9.5 and above.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Rand.py,v 1.2 2000/04/17 16:16:44 ngps Exp $'

import M2Crypto
m2 = M2Crypto

rand_seed           = m2.rand_seed
rand_add            = m2.rand_add
load_file           = m2.rand_load_file
save_file           = m2.rand_save_file
rand_bytes          = m2.rand_bytes
rand_pseudo_bytes   = m2.rand_pseudo_bytes

def estimate_entropy(buf):
    pass


