#!/usr/bin/env python

"""
Distutils installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2006 OSAF. All Rights Reserved.
"""

import os, sys

try:
    import setuptools # Must import setuptools before distutils
except ImportError:
    pass # test command not available
    
from distutils.core import setup, Extension
from distutils.command import build_ext 

def parse_args(option_dict):
    args = sys.argv[1:]
    for arg in args:
        if arg.startswith("--openssl"):
            option_dict['openssl_prefix'] = arg.split("=")[1]
            sys.argv.remove(arg)
            break
        
if os.name == 'nt':
    libraries = ['ssleay32', 'libeay32']
    option_dict = {'openssl_prefix': 'c:\\pkg'}
else:
    libraries = ['ssl', 'crypto']
    option_dict = {'openssl_prefix': '/usr'}
    
parse_args(option_dict)
	
include_dir = os.path.join(option_dict['openssl_prefix'], 'include')
include_dirs = [os.path.join(os.getcwd(), 'SWIG'), include_dir]
swig_opts_str = ''.join(('-I', include_dir))

library_dirs = [os.path.join(option_dict['openssl_prefix'], 'lib')]
if sys.platform == 'cygwin':
    # Cygwin SHOULD work (there's code in distutils), but
    # if one first starts a Windows command prompt, then bash,
    # the distutils code does not seem to work. If you start
    # Cygwin directly, then it would work even without this change.
    # Someday distutils will be fixed and this won't be needed.
    library_dirs += [os.path.join(option_dict['openssl_prefix'], 'bin')]


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

        swig_cmd.append(swig_opts_str)

        for source in swig_sources:
            target = swig_targets[source]
            self.announce("swigging %s to %s" % (source, target))
            self.spawn(swig_cmd + ["-o", target, source])

        return new_sources
    
    build_ext.build_ext.swig_sources = swig_sources

m2crypto = Extension(name='M2Crypto.__m2crypto',
                     sources = ['SWIG/_m2crypto.i'],
                     include_dirs = include_dirs,
                     library_dirs = library_dirs,
                     libraries = libraries,
                     extra_compile_args = ['-DTHREADING'],
                     #extra_link_args = ['-Wl,-search_paths_first'],
                     swig_opts = [swig_opts_str]
                     )

setup(name = 'M2Crypto',
      version = '0.17',
      description = 'M2Crypto: A Python crypto and SSL toolkit',
      long_description = 'M2Crypto is a wrapper for OpenSSL using SWIG.',
      license = 'BSD-style license',
      platforms = ['any'],
      author = 'Ng Pheng Siong',
      author_email = 'ngps@netmemetic.com',
      maintainer = 'Heikki Toivonen',
      maintainer_email = 'heikki@osafoundation.org',
      url = 'http://wiki.osafoundation.org/bin/view/Projects/MeTooCrypto',
      packages = ['M2Crypto', 'M2Crypto.SSL', 'M2Crypto.PGP'],
      ext_modules = [m2crypto],
      test_suite='tests.alltests.suite',
      )
