"""M2Crypto threading support. 

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: threading.py,v 1.1 1999/10/01 15:57:20 ngps Exp $'

import M2Crypto
m2=M2Crypto

def init():
    m2.threading_init()

def cleanup():
    m2.threading_cleanup()

