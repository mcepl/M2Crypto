"""M2Crypto wrapper for OpenSSL BIO API.

This is all a bit ad hoc and incoherent at the moment.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: BIO.py,v 1.1 1999/09/12 14:25:35 ngps Exp $'

import M2Crypto
m2=M2Crypto

m2.bio_init()

BIO_method={ \
	's_mem': m2.bio_s_mem, \
	's_socket': m2.bio_s_socket, \
	'f_ssl': m2.bio_f_ssl, \
	'f_buffer': m2.bio_f_buffer \
	}

class BIO:
	def __init__(self, method=None):
		if method is not None:
			self.bio=m2.bio_new(BIO_method[kw_args['method']]())
		self.closed=0

	def __del__(self):
		self.close()
		m2.bio_free(self.bio)

	def bio_ptr(self):
		# Friends only, please.
		return self.bio

	def readable(self):
		return 1

	def read(self, size=1024):
		if not self.readable():
			raise m2.Error("write-only") 
		if self.closed or size<=0:
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

	def close(self):
		self.closed=1


class IOBuffer(BIO):

	"""Class wrapper for BIO_f_buffer. Its principal function is to
	be BIO_push()'ed on top of a BIO_s_socket, so that makefile() of
	said socket works. Provides buffering for the underlying."""

	def __init__(self, bio_ptr, mode):
		self.io=m2.bio_new(m2.bio_f_buffer())
		self.bio=m2.bio_push(self.io, bio_ptr)
		self.closed=0
		if 'w' in mode:
			self.can_write=1
		else:
			self.can_write=0

	def __del__(self):
		m2.bio_pop(self.bio)
		m2.bio_free(self.io)

	def fileno(self):
		# XXX Caller is not expected to expect to do anything useful with this.
		return id(self)

	def readline(self, size=80):
		if self.closed:
			return None
		buf=m2.bio_gets(self.bio, size)
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


class Socket(BIO):

	"""Class wrapper for BIO_s_socket."""

	def __init__(self, sock_fileno, close_flag=0):
		BIO.__init__(self)
		self.bio=m2.bio_new_socket(sock_fileno, close_flag)


class MemoryBuffer(BIO):

	"""Class wrapper for BIO_s_mem."""

	def __init__(self, data=None):
		BIO.__init__(self)
		self.bio=m2.bio_new(m2.bio_s_mem())
		if data is not None:
			m2.bio_write(self.bio, data)

	def __len__(self):
		return m2.bio_ctrl_pending(self.bio)

	def read_all(self):
		try:
			return m2.bio_read(self.bio, m2.bio_ctrl_pending(self.bio))
		except:
			return ''
		
	getvalue=read_all

class File(BIO):

	"""Class wrapper for BIO_s_fp. This class is intended to interface Python
	and OpenSSL functions that expect BIO *. If you wish to manipulate files 
	in Python, use Python's file object."""

	def __init__(self, pyfile, close_flag=1):
		BIO.__init__(self)
		self.pyfile=pyfile
		self.close_flag=close_flag
		self.bio=m2.bio_new_fp(pyfile, close_flag)

	def close(self):
		if self.close_flag==1:
			self.pyfile.close()
		self.closed=1

def openfile(filename, mode='rb'):
	return File(open(filename, mode), 1)


