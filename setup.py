#!/usr/bin/env python

"""
Distutils installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.
"""

_RCS_id = '$Id: setup.py,v 1.13 2004/03/28 11:30:01 ngps Exp $'

import os, sys
from distutils.core import setup, Extension
from distutils.command import build_ext

if sys.version_info < (2,4):

    # This copy of swig_sources is from Python 2.2.

    def swig_sources (self, sources):

        """Walk the list of source files in 'sources', looking for SWIG
        interface (.i) files.  Run SWIG on all that are found, and
        return a modified 'sources' list with SWIG source files replaced
        by the generated C (or C++) files.
        """

        new_sources = []
        swig_sources = []
        swig_targets = {}

        # XXX this drops generated C/C++ files into the source tree, which
        # is fine for developers who want to distribute the generated
        # source -- but there should be an option to put SWIG output in
        # the temp dir.

        if self.swig_cpp:
            target_ext = '.cpp'
        else:
            target_ext = '.c'

        for source in sources:
            (base, ext) = os.path.splitext(source)
            if ext == ".i":             # SWIG interface file
                new_sources.append(base + target_ext)
                swig_sources.append(source)
                swig_targets[source] = new_sources[-1]
            else:
                new_sources.append(source)

        if not swig_sources:
            return new_sources

        swig = self.find_swig()
        swig_cmd = [swig, "-python", "-ISWIG"]
        if self.swig_cpp:
            swig_cmd.append("-c++")

        for source in swig_sources:
            target = swig_targets[source]
            self.announce("swigging %s to %s" % (source, target))
            self.spawn(swig_cmd + ["-o", target, source])

        return new_sources

    build_ext.build_ext.swig_sources = swig_sources

my_inc = os.path.join(os.getcwd(), 'SWIG')

if os.name == 'nt':
    openssl_dir = 'c:\\pkg\\openssl'
    include_dirs = [my_inc, openssl_dir + '/include']
    library_dirs = [openssl_dir + '\\lib']
    libraries = ['ssleay32', 'libeay32']
    
elif os.name == 'posix':
    include_dirs = [my_inc, '/usr/include']
    library_dirs = ['/usr/lib']
    if sys.platform == 'cygwin':
        library_dirs += ['/usr/bin'] # libpython is here
    libraries = ['ssl', 'crypto']

m2crypto = Extension(name = '__m2crypto',
                     sources = ['SWIG/_m2crypto.i'],
                     include_dirs = include_dirs,
                     library_dirs = library_dirs,
                     libraries = libraries,
                     extra_compile_args = ['-DTHREADING', 
                                           '-DSWIG_COBJECT_PYTHON']
                     )

setup(name = 'M2Crypto',
    version = '0.13',
    description = 'M2Crypto: A Python crypto and SSL toolkit',
    author = 'Ng Pheng Siong',
    author_email = 'ngps@netmemetic.com',
    url = 'http://sandbox.rulemaker.net/ngps/m2/',
    packages = ['M2Crypto', 'M2Crypto.SSL', 'M2Crypto.PGP'],
    ext_package = 'M2Crypto',
    ext_modules = [m2crypto]
    )

