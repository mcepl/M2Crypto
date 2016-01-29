#!/usr/bin/env python

"""
setuptools based installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.
"""
import os
import platform
import sys

import setuptools

from distutils.command import build
from distutils.file_util import copy_file
from setuptools.command import build_ext

if sys.version_info[:2] <= (2, 6):
    # This covers hopefully only RHEL-6 (users of any other 2.6 Pythons
    # ... Solaris?, *BSD? ... should file an issue and be prepared to
    # help with adjusting this script.
    requires_list = ["unittest2"]
    _multiarch = ""
else:
    requires_list = []
    import sysconfig
    _multiarch = sysconfig.get_config_var("MULTIARCH")


class _M2CryptoBuild(build.build):
    '''Specialization of build to enable swig_opts to inherit any
    include_dirs settings made at the command line or in a setup.cfg file'''
    user_options = build.build.user_options + \
        [('openssl=', 'o', 'Prefix for openssl installation location')]

    def initialize_options(self):
        '''Overload to enable custom openssl settings to be picked up'''

        build.build.initialize_options(self)
        self.openssl = None


class _M2CryptoBuildExt(build_ext.build_ext):
    '''Specialization of build_ext to enable swig_opts to inherit any
    include_dirs settings made at the command line or in a setup.cfg file'''
    user_options = build_ext.build_ext.user_options + \
        [('openssl=', 'o', 'Prefix for openssl installation location')]

    def initialize_options(self):
        '''Overload to enable custom openssl settings to be picked up'''
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

        _openssl = next((x.split('=')[1] for x in sys.argv
                         if '--openssl=' in x), None)
        if _openssl and os.path.isdir(_openssl):
            self.openssl = _openssl

        self.include_dirs.append(os.path.join(self.openssl, 'include'))
        openssl_library_dir = os.path.join(self.openssl, 'lib')

        if platform.system() == "Linux":
            if _multiarch:  # on Fedora/RHEL it is an empty string
                self.include_dirs.append(
                    os.path.join(self.openssl, 'include', _multiarch))
            else:
                self.include_dirs.append(
                    os.path.join(self.openssl, 'include', 'openssl'))

            self.swig_opts.append('-D__%s__' % platform.machine().lower())

        self.swig_opts.extend(['-I%s' % i for i in self.include_dirs])
        self.swig_opts.append('-includeall')
        self.swig_opts.append('-modern')
        self.swig_opts.append('-builtin')

        # These two lines are a workaround for
        # http://bugs.python.org/issue2624 , hard-coding that we are only
        # building a single extension with a known path; a proper patch to
        # distutils would be in the run phase, when extension name and path are
        # known.
        self.swig_opts.append('-outdir')
        self.swig_opts.append(os.path.join(self.build_lib, 'M2Crypto'))

        self.include_dirs.append(os.path.join(os.getcwd(), 'SWIG'))

        if sys.platform == 'cygwin':
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [os.path.join(self.openssl, 'bin')]

        self.library_dirs += [os.path.join(self.openssl, openssl_library_dir)]

    def run(self):
        '''Overloaded build_ext implementation to allow inplace=1 to work,
        which is needed for (python setup.py test).'''
        # This is another workaround for http://bugs.python.org/issue2624 + the
        # corresponding lack of support in setuptools' test command. Note that
        # just using self.inplace in finalize_options() above does not work
        # because swig is not rerun if the __m2crypto.so extension exists.
        # Again, hard-coding our extension name and location.
        build_ext.build_ext.run(self)
        if self.inplace:
            copy_file(os.path.join(self.build_lib, 'M2Crypto', '_m2crypto.py'),
                      os.path.join('M2Crypto', '_m2crypto.py'),
                      verbose=self.verbose, dry_run=self.dry_run)

if sys.platform == 'darwin':
    my_extra_compile_args = ["-Wno-deprecated-declarations"]
else:
    my_extra_compile_args = []

m2crypto = setuptools.Extension(name='M2Crypto.__m2crypto',
                                sources=['SWIG/_m2crypto.i'],
                                extra_compile_args=['-DTHREADING'],
                                # Uncomment to build Universal Mac binaries
                                # extra_link_args =
                                #     ['-Wl,-search_paths_first'],
                                )

long_description_text = '''\
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to Python's
httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies for web
session management; FTP/TLS client and server; S/MIME; ZServerSSL: A HTTPS
server for Zope and ZSmime: An S/MIME messenger for Zope. M2Crypto can also be
used to provide SSL for Twisted.'''

setuptools.setup(
    name='M2Crypto',
    version='0.23.0',
    description='M2Crypto: A Python crypto and SSL toolkit',
    long_description=long_description_text,
    license='BSD-style license',
    platforms=['any'],
    author='Ng Pheng Siong',
    author_email='ngps at sandbox rulemaker net',
    maintainer='Matej Cepl',
    maintainer_email='mcepl@cepl.eu',
    url='https://gitlab.com/m2crypto/m2crypto',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='cryptography openssl',
    packages=setuptools.find_packages(exclude=['contrib', 'docs', 'tests']),
    ext_modules=[m2crypto],
    test_suite='tests.alltests.suite',
    install_requires=requires_list,
    cmdclass={
        'build_ext': _M2CryptoBuildExt,
        'build': _M2CryptoBuild
    }
)
