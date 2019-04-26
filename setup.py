#!/usr/bin/env python

"""
setuptools based installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.

Copyright 2018 Daniel Wozniak. All rights reserved.
"""
import glob
import logging
import os
import platform
import re
import string
import subprocess
import sys
import shutil

from distutils.command import build, sdist
from distutils.command.clean import clean
from distutils.dir_util import mkpath
from distutils.version import StrictVersion

import setuptools
from setuptools.command import build_ext

logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    stream=sys.stdout, level=logging.INFO)
log = logging.getLogger('setup')

REQUIRED_SWIG_VERSION = '2.0.4'

if (2, 6) < sys.version_info[:2] < (3, 5):
    requires_list = ['typing']
else:
    requires_list = []
package_data = {}
if sys.platform == 'win32':
    package_data.update(M2Crypto=["*.dll"])


def _get_additional_includes():
    if os.name == 'nt':
        globmask = os.path.join('C:', os.sep, 'Program Files*',
                                '*Visual*', 'VC', 'include')
        err = glob.glob(globmask)
    else:
        pid = subprocess.Popen(os.environ.get('CPP', 'cpp').split() +
                               ['-Wp,-v', '-'],
                               stdin=open(os.devnull, 'r'),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        _, err = pid.communicate()
        err = [line.lstrip() for line in err.decode('utf8').split('\n')
               if line and line.startswith(' /')]

    log.debug('additional includes:\n%s', err)
    return err


def openssl_version(ossldir, req_ver, required=False):
    # type: (str, int, bool) -> bool
    """
    Compare version of the installed OpenSSL with the maximum required version.

    :param ossldir: the directory where OpenSSL is installed
    :param req_ver: required version as integer (e.g. 0x10100000)
    :param required: whether we want bigger-or-equal or less-than
    :return: Boolean indicating whether the satisfying version of
             OpenSSL has been installed.
    """
    ver = None
    file = os.path.join(ossldir, 'include', 'openssl', 'opensslv.h')

    with open(file) as origin_file:
        for line in origin_file:
            m = re.match(r'^# *define  *OPENSSL_VERSION_NUMBER  *(0x[0-9a-fA-F]*)', line)
            if m:
                log.debug('found version number: %s\n' % m.group(1))
                ver = int(m.group(1), base=16)
                break

    if ver is None:
        raise OSError('Unknown format of file %s\n' % file)

    if required:
        return ver >= req_ver
    else:
        return ver < req_ver


class _M2CryptoBuild(build.build):
    """Enable swig_opts to inherit any include_dirs settings made elsewhere."""

    user_options = build.build.user_options + \
        [('openssl=', 'o', 'Prefix for openssl installation location')] + \
        [('bundledlls', 'b', 'Bundle DLLs (win32 only)')]

    def initialize_options(self):
        """Overload to enable custom openssl settings to be picked up."""
        build.build.initialize_options(self)
        self.openssl = None
        self.bundledlls = None


class _M2CryptoBuildExt(build_ext.build_ext):
    """Enable swig_opts to inherit any include_dirs settings made elsewhere."""

    user_options = build_ext.build_ext.user_options + \
        [('openssl=', 'o', 'Prefix for openssl installation location')] + \
        [('bundledlls', 'b', 'Bundle DLLs (win32 only)')]

    def initialize_options(self):
        """Overload to enable custom openssl settings to be picked up."""
        build_ext.build_ext.initialize_options(self)
        self.openssl = None
        self.bundledlls = None

    def finalize_options(self):
        # type: (None) -> None
        """Append custom openssl include file and library linking options."""
        build_ext.build_ext.finalize_options(self)
        self.openssl_default = None
        self.set_undefined_options('build', ('openssl', 'openssl'))
        if self.openssl is None:
            self.openssl = self.openssl_default
        self.set_undefined_options('build', ('bundledlls', 'bundledlls'))

        self.libraries = ['ssl', 'crypto']
        if sys.platform == 'win32':
            self.libraries = ['ssleay32', 'libeay32']
            if self.openssl and openssl_version(self.openssl, 0x10100000, True):
                self.libraries = ['libssl', 'libcrypto']
                self.swig_opts.append('-D_WIN32')
                # Swig doesn't know the version of MSVC, which causes errors in e_os2.h
                # trying to import stdint.h. Since python 2.7 is intimately tied to
                # MSVC 2008, it's harmless for now to define this. Will come back to
                # this shortly to come up with a better fix.
                self.swig_opts.append('-D_MSC_VER=1500')


        if sys.version_info[:1] >= (3,):
            self.swig_opts.append('-py3')

        log.debug('self.include_dirs = %s', self.include_dirs)
        log.debug('self.library_dirs = %s', self.library_dirs)

        if self.openssl is not None:
            log.debug('self.openssl = %s', self.openssl)
            openssl_library_dir = os.path.join(self.openssl, 'lib')
            openssl_include_dir = os.path.join(self.openssl, 'include')

            self.library_dirs.append(openssl_library_dir)
            self.include_dirs.append(openssl_include_dir)

            log.debug('self.include_dirs = %s', self.include_dirs)
            log.debug('self.library_dirs = %s', self.library_dirs)

        if platform.system() == "Linux":
            # For RedHat-based distros, the '-D__{arch}__' option for
            # Swig needs to be normalized, particularly on i386.
            mach = platform.machine().lower()
            if mach in ('i386', 'i486', 'i586', 'i686'):
                arch = '__i386__'
            elif mach in ('ppc64', 'powerpc64', 'ppc64le', 'ppc64el'):
                arch = '__powerpc64__'
            elif mach in ('ppc', 'powerpc'):
                arch = '__powerpc__'
            else:
                arch = '__%s__' % mach
            self.swig_opts.append('-D%s' % arch)
            if mach in ('ppc64le', 'ppc64el'):
                self.swig_opts.append('-D_CALL_ELF=2')

        self.swig_opts.extend(['-I%s' % i for i in self.include_dirs])

        # Some Linux distributor has added the following line in
        # /usr/include/openssl/opensslconf.h:
        #
        #     #include "openssl-x85_64.h"
        #
        # This is fine with C compilers, because they are smart enough to
        # handle 'local inclusion' correctly.  Swig, on the other hand, is
        # not as smart, and needs to be told where to find this file...
        #
        # Note that this is risky workaround, since it takes away the
        # namespace that OpenSSL uses.  If someone else has similarly
        # named header files in /usr/include, there will be clashes.
        if self.openssl is None:
            self.swig_opts.append('-I/usr/include/openssl')
        else:
            self.swig_opts.append('-I' + os.path.join(openssl_include_dir, 'openssl'))

        # swig seems to need the default header file directories
        self.swig_opts.extend(['-I%s' % i for i in _get_additional_includes()])
        self.swig_opts.append('-includeall')
        self.swig_opts.append('-modern')
        self.swig_opts.append('-builtin')

        # These two lines are a workaround for
        # http://bugs.python.org/issue2624 , hard-coding that we are only
        # building a single extension with a known path; a proper patch to
        # distutils would be in the run phase, when extension name and path are
        # known.
        self.swig_opts.extend(['-outdir',
                              os.path.join(os.getcwd(), 'M2Crypto')])
        self.include_dirs.append(os.path.join(os.getcwd(), 'SWIG'))

        if sys.platform == 'cygwin' and self.openssl is not None:
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [os.path.join(self.openssl, 'bin')]

        mkpath(os.path.join(self.build_lib, 'M2Crypto'))

    def run(self):
        """
        On Win32 platforms include the openssl dll's in the binary packages
        """

        # Win32 bdist builds must use --openssl in the builds step.
        if not self.bundledlls:
           build_ext.build_ext.run(self)
           return

        if sys.platform == 'win32':
            ver_part = ''
            if self.openssl and openssl_version(self.openssl, 0x10100000, True):
                ver_part += '-1_1'
            if sys.maxsize > 2**32:
                ver_part += '-x64'
            search = list(self.library_dirs)
            if self.openssl:
                search = search + [self.openssl, os.path.join(self.openssl, 'bin')]
            libs = list(self.libraries)
            for libname in list(libs):
                for search_path in search:
                     dll_name = '{0}{1}.dll'.format(libname, ver_part)
                     dll_path = os.path.join(search_path, dll_name)
                     if os.path.exists(dll_path):
                        shutil.copy(dll_path, 'M2Crypto')
                        libs.remove(libname)
                        break
            if libs:
                raise Exception("Libs not found {}".format(','.join(libs)))
        build_ext.build_ext.run(self)


def swig_version(req_ver):
    # type: (str) -> bool
    """
    Compare version of the swig with the required version.

    :param req_ver: required version as a str (e.g., '2.0.4')
    :return: Boolean indicating whether the satisfying version of swig
             has been installed.
    """
    ver_str = None
    IND_VER_LINE = 'SWIG Version '

    try:
        pid = subprocess.Popen(['swig', '-version'], stdout=subprocess.PIPE)
    except OSError:
        return False

    out, _ = pid.communicate()
    if hasattr(out, 'decode'):
        out = out.decode('utf8')

    for line in out.split('\n'):
        line = line.strip()
        if line.startswith(IND_VER_LINE):
            ver_str = line.strip()[len(IND_VER_LINE):]
            break

    if not ver_str:
        raise OSError('Unknown format of swig -version output:\n%s' % out)

    return StrictVersion(ver_str) >= StrictVersion(req_ver)


x_comp_args = set()

# We take care of deprecated functions in OpenSSL with our code, no need
# to spam compiler output with it.
if sys.platform == 'win32':
    x_comp_args.update(['-DTHREADING', '-D_CRT_SECURE_NO_WARNINGS'])
else:
    x_comp_args.update(['-DTHREADING', '-Wno-deprecated-declarations'])

# Don't try to run swig on the ancient platforms
if swig_version(REQUIRED_SWIG_VERSION):
    lib_sources = ['SWIG/_m2crypto.i']
else:
    lib_sources = ['SWIG/_m2crypto_wrap.c']


m2crypto = setuptools.Extension(name='M2Crypto._m2crypto',
                                sources=lib_sources,
                                extra_compile_args=list(x_comp_args),
                                # Uncomment to build Universal Mac binaries
                                # extra_link_args =
                                #     ['-Wl,-search_paths_first'],
                                )


class Clean(clean):
    def __init__(self, dist):
        clean.__init__(self, dist)

    def initialize_options(self):
        clean.initialize_options(self)
        self.all = True

    def finalize_options(self):
        clean.finalize_options(self)

    def run(self):
        clean.run(self)
        garbage_list = [
            os.path.join('M2Crypto', '*.so'),
            os.path.join('M2Crypto', '*.pyd'),
            os.path.join('M2Crypto', '*.dll')
        ]
        for p in garbage_list:
            for f in glob.glob(p):
                if os.path.exists(f):
                    os.unlink(f)

def __get_version():  # noqa
    with open('M2Crypto/__init__.py') as init_file:
        for line in init_file:
            if line.startswith('__version__ ='):
                return line.split('=')[1].strip(string.whitespace + "'")


long_description_text = '''\
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to Python's
httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies for web
session management; FTP/TLS client and server; S/MIME; M2Crypto can also be
used to provide SSL for Twisted. Smartcards supported through the Engine
interface.'''

setuptools.setup(
    name='M2Crypto',
    version=__get_version(),
    description='M2Crypto: A Python crypto and SSL toolkit',
    long_description=long_description_text,
    license='MIT',
    platforms=['any'],
    author='Ng Pheng Siong',
    author_email='ngps@sandbox.rulemaker.net',
    maintainer='Matej Cepl',
    maintainer_email='mcepl@cepl.eu',
    url='https://gitlab.com/m2crypto/m2crypto',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='cryptography openssl',
    packages=setuptools.find_packages(exclude=['contrib', 'docs', 'tests']),
    ext_modules=[m2crypto],
    test_suite='tests.alltests.suite',
    install_requires=requires_list,
    package_data=package_data,
    cmdclass={
        'build_ext': _M2CryptoBuildExt,
        'build': _M2CryptoBuild,
        'clean': Clean
    }
)
