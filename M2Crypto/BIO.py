"""M2Crypto wrapper for OpenSSL BIO API.

This is all a bit ad hoc and incoherent at the moment.

Copyright (c) 1999, 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: BIO.py,v 1.3 2000/04/01 14:49:38 ngps Exp $'

import M2Crypto
m2=M2Crypto

m2.bio_init()

class BIO:
    def __init__(self, bio, _pyfree=0):
        self.bio = bio
        self._pyfree = _pyfree
        self.closed = 0

    def __del__(self):
        self.close()
        if self._pyfree:
            m2.bio_free(self.bio)

    def _ptr(self):
        # Friends only, please.
        return self.bio

    # Deprecated.
    bio_ptr = _ptr

    def readable(self):
        return 1

    def read(self, size=4096):
        if not self.readable():
            raise m2.Error("write-only") 
        if self.closed or size <= 0:
            return ''
        try:
            return m2.bio_read(self.bio, size)
        except RuntimeError:
            # XXX better error handling
            return ''

    def writeable(self):
        return 1

    def write(self, data):
        if not self.writeable():
            raise m2.Error("read-only") 
        if self.closed:
            return 0
        return m2.bio_write(self.bio, data)

    def flush(self):
        m2.bio_flush(self.bio)

    def close(self):
        self.closed = 1


class MemoryBuffer(BIO):

    """Object wrapper for BIO_s_mem."""

    def __init__(self, data=None):
        BIO.__init__(self, None)
        self.bio = m2.bio_new(m2.bio_s_mem())
        self._pyfree = 1
        if data is not None:
            m2.bio_write(self.bio, data)

    def __len__(self):
        return m2.bio_ctrl_pending(self.bio)

    def read_all(self):
        try:
            return m2.bio_read(self.bio, m2.bio_ctrl_pending(self.bio))
        except:
            return ''
        
    # StringIO-compatibility.
    getvalue = read_all


class File(BIO):

    """Object wrapper for BIO_s_fp. This class is intended to interface Python
    and OpenSSL functions that expect BIO *. If you wish to manipulate files 
    in Python, use Python's file object."""

    def __init__(self, pyfile, close_flag=0):
        BIO.__init__(self, None)
        self.pyfile = pyfile
        self.close_flag = close_flag
        self.bio=m2.bio_new_fp(pyfile, 0)
        self._pyfree = 1

    def __del__(self):
        m2.bio_free(self.bio)
        self.pyfile.close()

def openfile(filename, mode='rb'):
    return File(open(filename, mode), 1)


