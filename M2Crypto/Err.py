"""M2Crypto wrapper for OpenSSL Error API.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Err.py,v 1.1 1999/10/01 15:56:44 ngps Exp $'

import BIO
import M2Crypto
m2=M2Crypto

def get_error():
    err=BIO.MemoryBuffer()
    m2.err_print_errors(err.bio_ptr())
    return err.getvalue()

