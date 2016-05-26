"""Support for SSL socket timeouts.

Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved.

Copyright 2008 Heikki Toivonen. All rights reserved.
"""

__all__ = ['DEFAULT_TIMEOUT', 'timeout', 'struct_to_timeout', 'struct_size']

import struct
from M2Crypto import m2  # noqa

DEFAULT_TIMEOUT = 600  # type: int


class timeout:

    def __init__(self, sec=DEFAULT_TIMEOUT, microsec=0):
        # type: (int, int) -> None
        self.sec = sec
        self.microsec = microsec

    def pack(self):
        return struct.pack('ll', self.sec, self.microsec)


def struct_to_timeout(binstr):
    # type: (bytes) -> timeout
    (s, ms) = struct.unpack('ll', binstr)
    return timeout(s, ms)


def struct_size():
    # type: () -> int
    return struct.calcsize('ll')
