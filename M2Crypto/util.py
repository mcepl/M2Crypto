from __future__ import absolute_import

"""
    M2Crypto utility routines.

    Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

    Portions created by Open Source Applications Foundation (OSAF) are
    Copyright (C) 2004 OSAF. All Rights Reserved.
"""

import binascii
import logging
import sys

from M2Crypto import m2, six

log = logging.getLogger('util')

# Python 2 has int() and long().
# Python 3 and higher only has int().
# Work around this.
if sys.version_info > (3,):
    long = int
    unicode = str


class UtilError(Exception):
    pass

m2.util_init(UtilError)


def pkcs5_pad(data, blklen=8):
    pad = (8 - (len(data) % 8))
    return data + chr(pad) * pad


def pkcs7_pad(data, blklen):
    if blklen > 255:
        raise ValueError('illegal block size')
    pad = (blklen - (len(data) % blklen))
    return data + chr(pad) * pad


def py3ord(x):
    return ord(x) if not isinstance(x, int) else x


# before the introduction of py3{bytes,str}, python2 code
# was just using args as-is
if six.PY2:
    def py3bytes(x):
        return x

    def py3str(x):
        return x
else:
    def py3bytes(x):
        return x if isinstance(x, bytes) else bytes(x, encoding="ascii")

    def py3str(x):
        return x if isinstance(x, str) else x.decode("ascii")


def octx_to_num(x):
    return int(binascii.hexlify(x), 16)


def genparam_callback(p, n, out=sys.stdout):
    ch = ['.', '+', '*', '\n']
    out.write(ch[p])
    out.flush()


def quiet_genparam_callback(p, n, out):
    pass


def passphrase_callback(v, prompt1='Enter passphrase:',
                        prompt2='Verify passphrase:'):
    from getpass import getpass
    while 1:
        try:
            p1 = getpass(prompt1)
            if v:
                p2 = getpass(prompt2)
                if p1 == p2:
                    break
            else:
                break
        except KeyboardInterrupt:
            return None
    return p1


def no_passphrase_callback(*args):
    return ''
