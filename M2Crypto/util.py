"""M2Crypto utility routines.

Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: util.py,v 1.4 2000/02/23 15:43:09 ngps Exp $'

import sys
import M2Crypto
m2 = M2Crypto

def h2b(s):
    import array, string
    ar=array.array('c')
    start=0
    if s[:2]=='0x':
        start=2
    for i in range(start, len(s), 2):
        num=string.atoi("0x%s"%(s[i:i+2],), 16)
        ar.append(chr(num))
    return ar.tostring()        


def pkcs5_pad(data, blklen=8):
    pad=(8-(len(data)%8))
    return data+chr(pad)*pad


def pkcs7_pad(data, blklen):
    if blklen>255:
        raise ValueError, 'illegal block size'
    pad=(blklen-(len(data)%blklen))
    return data+chr(pad)*pad


def passphrase_callback(v, prompt1='Enter passphrase:', prompt2='Verify passphrase:'):
    from getpass import getpass
    while 1:
        try:
            p1=getpass(prompt1)
            if v:
                p2=getpass(prompt2)
                if p1==p2:
                    break
            else:
                break
        except KeyboardInterrupt:
            return None
    return p1


def genparam_callback(p, n):
    from sys import stdout
    ch=['.','+','*','\n']
    stdout.write(ch[p])
    stdout.flush()


def octx_to_num(x):
    v = 0L
    lx = len(x)
    for i in range(lx):
        v = v + ord(x[i]) * (256L ** (lx-i-1))
    return v

