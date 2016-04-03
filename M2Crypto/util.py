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

# This means "Python 2.7 or higher" so it is True for py3k as well
py27plus = sys.version_info[:2] > (2, 6)  # type: bool

from M2Crypto import m2, six
if py27plus:
    from typing import AnyStr, Tuple, Union  # noqa
    # see https://github.com/python/typeshed/issues/222
    AddrType = Union[Tuple[str, int], str]

log = logging.getLogger('util')


class UtilError(Exception):
    pass

m2.util_init(UtilError)


def pkcs5_pad(data, blklen=8):
    # type: (str, int) -> str
    pad = (8 - (len(data) % 8))
    return data + chr(pad) * pad


def pkcs7_pad(data, blklen):
    # type: (str, int) -> str
    if blklen > 255:
        raise ValueError('illegal block size')
    pad = (blklen - (len(data) % blklen))
    return data + chr(pad) * pad


# before the introduction of py3{bytes,str}, python2 code
# was just using args as-is
if six.PY2:
    def py3bytes(x):
        # type: (bytes) -> bytes
        return x

    def py3str(x):
        # type: (str) -> str
        return x
else:
    def py3bytes(x):
        # type: (AnyStr) -> bytes
        return x if isinstance(x, bytes) else bytes(x, encoding="ascii")

    def py3str(x):
        # type: (AnyStr) -> str
        return x if isinstance(x, str) else x.decode("ascii")


def bin_to_hex(b):
    # type: (bytes) -> str
    return py3str(binascii.b2a_base64(b)[:-1])


def octx_to_num(x):
    # type: (bytes) -> int
    return int(binascii.hexlify(x), 16)


def genparam_callback(p, n, out=sys.stdout):
    # type: (int, Any, file) -> None
    ch = ['.', '+', '*', '\n']
    out.write(ch[p])
    out.flush()


def quiet_genparam_callback(p, n, out):
    # type: (Any, Any, Any) -> None
    pass


def passphrase_callback(v, prompt1='Enter passphrase:',
                        prompt2='Verify passphrase:'):
    # type: (bool, str, str) -> Optional[str]
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
    # type: (List[Any]) -> str
    return ''
