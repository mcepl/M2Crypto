from __future__ import absolute_import

"""M2Crypto wrapper for OpenSSL PRNG. Requires OpenSSL 0.9.5 and above.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

from M2Crypto import m2, util
if util.py27plus:
    from typing import AnyStr, List  # noqa


__all__ = ['rand_seed', 'rand_add', 'load_file', 'save_file', 'rand_bytes',
           'rand_pseudo_bytes', 'rand_file_name', 'rand_status']

rand_seed = m2.rand_seed  # type: (bytes) -> None
rand_add = m2.rand_add  # type: (bytes, float) -> None
load_file = m2.rand_load_file  # type: (AnyStr, int) -> int
save_file = m2.rand_save_file  # type: (AnyStr) -> int
rand_bytes = m2.rand_bytes  # type: (int) -> bytes
rand_pseudo_bytes = m2.rand_pseudo_bytes  # type: (int) -> Tuple[bytes, int]
rand_status = m2.rand_status  # type: () -> int


def rand_file_name():
    # type: () -> bytes
    return m2.rand_file_name()
