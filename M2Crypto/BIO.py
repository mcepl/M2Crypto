"""M2Crypto wrapper for OpenSSL BIO API.

This is all a bit ad hoc and incoherent at the moment.

Copyright (c) 1999, 2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: BIO.py,v 1.4 2000/04/17 16:13:11 ngps Exp $'

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

    def reset(self):
        m2.bio_reset(self.bio)

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

    def read(self, size=0):
        if size:
            return m2.bio_read(self.bio, size)
        else:
            return m2.bio_read(self.bio, m2.bio_ctrl_pending(self.bio))
            
    #def read_all(self):
    #    return m2.bio_read(self.bio, m2.bio_ctrl_pending(self.bio))
        
    # Backwards-compatibility.
    getvalue = read_all = read


class File(BIO):

    """Object wrapper for BIO_s_fp. This class is intended to interface Python
    and OpenSSL functions that expect BIO *. For general file manipulation in
    Python, use Python's file object."""

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


class IOBuffer(BIO):

    """Object wrapper for BIO_f_buffer. Its principal function is to
    be BIO_push()'ed on top of a BIO_f_ssl, so that makefile() of
    said underlying SSL socket works."""

    def __init__(self, bio_ptr, mode, _pyfree=1):
        self.io = m2.bio_new(m2.bio_f_buffer())
        self.bio = m2.bio_push(self.io, bio_ptr)
        self.closed = 0
        if 'w' in mode:
            self.can_write=1
        else:
            self.can_write=0
        self._pyfree = _pyfree

    def __del__(self):
        if self._pyfree:
            m2.bio_pop(self.bio)
            m2.bio_free(self.io)

    def fileno(self):
        # XXX Caller is not expected to expect to do anything useful with this.
        return id(self)

    def readline(self, size=80):
        if self.closed:
            return None
        buf = m2.bio_gets(self.bio, size)
        if buf is None:
            return ''
        return buf

    def readlines(self, sizehint='ignored'):
        if self.closed:
            return []
        lines=[]
        while 1:
            buf=m2.bio_gets(self.bio, 80)
            if buf is None:
                break
            lines.append(buf)
        return lines

    def writeable(self):
        return self.can_write

