#!/usr/bin/env python

"""
Distutils installer for M2Crypto.

Copyright (c) 1999-2003, Ng Pheng Siong. All rights reserved.
"""

_RCS_id = '$Id: setup.py,v 1.4 2002/12/29 12:53:57 ngps Exp $'

import os, shutil
from distutils.core import setup, Extension

# Set up paths.
my_inc = 'swig'

if os.name == 'nt':
    openssl_dir = 'c:\\pkg\\openssl'
    include_dirs = [my_inc, openssl_dir + '/include']
    library_dirs = [openssl_dir + '\\lib']
    libraries = ['ssleay32', 'libeay32']
    #libraries = ['ssleay32_bc', 'libeay32_bc']

elif os.name == 'posix':
    include_dirs = [my_inc, '/usr/local/include']
    library_dirs = ['/usr/local/lib']
    libraries = ['ssl', 'crypto']

# Describe the module.
m2crypto = Extension(name = '__m2crypto',
                     sources = ['swig/_m2crypto.i'],
                     include_dirs = include_dirs,
                     library_dirs = library_dirs,
                     libraries = libraries 
                     )

setup(name = 'M2Crypto',
    version = '0.08',
    description = 'M2Crypto: A Python interface to OpenSSL',
    author = 'Ng Pheng Siong',
    author_email = 'ngps@netmemetic.com',
    url = 'http://www.post1.com/home/ngps/m2/',
    packages = ['M2Crypto', 'M2Crypto.SSL', 'M2Crypto.PGP'],
    ext_package = 'M2Crypto',
    ext_modules = [m2crypto]
    )

