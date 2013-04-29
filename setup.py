#!/usr/bin/env python

"""
Distutils/setuptools installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2009 Heikki Toivonen. All rights reserved.
"""

import os, sys, platform

from setuptools import setup
from setuptools.command import build_ext

from distutils.core import Extension


class _M2CryptoBuildExt(build_ext.build_ext):
    '''Specialization of build_ext to enable swig_opts to inherit any 
    include_dirs settings made at the command line or in a setup.cfg file'''
    user_options = build_ext.build_ext.user_options + \
            [('openssl=', 'o', 'Prefix for OpenSSL installation location')]

    def initialize_options(self):
        '''Overload to enable custom OpenSSL settings to be picked up'''

        build_ext.build_ext.initialize_options(self)
        
        # openssl is the attribute corresponding to openssl directory prefix
        # command line option
        if os.name == 'nt':
            self.libraries = ['ssleay32', 'libeay32']
            self.openssl = 'c:\\pkg'
        else:
            self.libraries = ['ssl', 'crypto']
            self.openssl = '/usr'
       
    
    def finalize_options(self):
        '''Overloaded build_ext implementation to append custom openssl
        include file and library linking options'''

        build_ext.build_ext.finalize_options(self)

        opensslIncludeDir = os.path.join(self.openssl, 'include')
        opensslLibraryDir = os.path.join(self.openssl, 'lib')
        
        self.swig_opts = ['-I%s' % i for i in self.include_dirs + \
                          [opensslIncludeDir, os.path.join(opensslIncludeDir, "openssl")]]
        self.swig_opts.append('-includeall')
        self.swig_opts.append('-modern')

        # Fedora does hat tricks.
        if platform.linux_distribution()[0] in ['Fedora', 'CentOS']:
            if platform.architecture()[0] == '64bit':
                self.swig_opts.append('-D__x86_64__')
            elif platform.architecture()[0] == '32bit':
                self.swig_opts.append('-D__i386__')

        self.include_dirs += [os.path.join(self.openssl, opensslIncludeDir),
                              os.path.join(os.getcwd(), 'SWIG')]

        if sys.platform == 'cygwin':
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [os.path.join(self.openssl, 'bin')]
               
        self.library_dirs += [os.path.join(self.openssl, opensslLibraryDir)]


m2crypto = Extension(name = 'M2Crypto.__m2crypto',
                     sources = ['SWIG/_m2crypto.i'],
                     extra_compile_args = ['-DTHREADING'],
                     #extra_link_args = ['-Wl,-search_paths_first'], # Uncomment to build Universal Mac binaries
                     )

setup(name = 'M2Crypto',
      version = '0.22',
      description = 'M2Crypto: A Python crypto and SSL toolkit',
      long_description = '''\
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to Python's
httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies for web
session management; FTP/TLS client and server; S/MIME; ZServerSSL: A HTTPS
server for Zope and ZSmime: An S/MIME messenger for Zope. M2Crypto can also be
used to provide SSL for Twisted. Smartcards supported through the Engine
interface.''',
      license = 'BSD-style license',
      platforms = ['any'],
      author = 'Ng Pheng Siong',
      author_email = 'ngps at sandbox rulemaker net',
      maintainer = 'Heikki Toivonen',
      maintainer_email = 'heikki@osafoundation.org',
      url = 'http://chandlerproject.org/Projects/MeTooCrypto',
      packages = ['M2Crypto', 'M2Crypto.SSL'],
      classifiers = [
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Operating System :: OS Independent',
          'Programming Language :: C',
          'Programming Language :: Python',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],

      ext_modules = [m2crypto],
      test_suite='tests.alltests.suite',
      cmdclass = {'build_ext': _M2CryptoBuildExt}
      )
