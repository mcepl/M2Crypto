#!/usr/bin/env python

"""A cheesy setup.py that bypasses SWIG and uses bundled versions of
_m2crypto_wrap.c and _m2crypto.py.

Copyright (c) 1999-2002, Ng Pheng Siong. All rights reserved.
"""

_RCS_id = '$Id: setup.py,v 1.2 2002/03/05 15:06:21 ngps Exp $'

import os, shutil
from distutils.core import setup, Extension

# Set up paths.
my_inc = 'swig'

if os.name == 'nt':
    openssl_dir = 'c:/pkg/openssl'
    include_dirs = [my_inc, openssl_dir + '/include']
    library_dirs = [openssl_dir + '/lib']
    libraries = ['libeay32', 'ssleay32']

elif os.name == 'posix':
    include_dirs = [my_inc, '/usr/local/include']
    library_dirs = ['/usr/local/lib']
    libraries = ['ssl', 'crypto']


# Copy the SWIG-generated .c file.
cfile = '_m2crypto_wrap.c'
src = 'swigout' + os.sep + cfile
dst = 'swig' + os.sep + cfile
shutil.copyfile(src, dst)
cfile = dst

# Copy the SWIG-generated .py file.
pyfile = '_m2crypto.py'
src = 'swigout' + os.sep + pyfile
dst = 'M2Crypto' + os.sep + pyfile
shutil.copyfile(src, dst)

# Describe the module.
m2crypto = Extension(name = '_m2cryptoc',
                        sources = [cfile],
                        include_dirs = include_dirs,
                        library_dirs = library_dirs,
                        libraries = libraries 
                        )

setup(name = 'M2Crypto',
    version = '0.07-snap3',
    description = 'M2Crypto: A Python interface to OpenSSL',
    author = 'Ng Pheng Siong',
    author_email = 'ngps@netmemetic.com',
    url = 'http://www.post1.com/home/ngps/m2/',
    packages = ['M2Crypto', 'M2Crypto.SSL', 'M2Crypto.PGP'],
    ext_package = 'M2Crypto',
    ext_modules = [m2crypto]
    )

