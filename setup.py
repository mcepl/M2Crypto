#!/usr/bin/env python

"""
setuptools based installer for M2Crypto.

Copyright (c) 1999-2004, Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.

Copyright 2018 Daniel Wozniak. All rights reserved.
"""
import ctypes
import ctypes.util
import glob
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import setuptools
import distutils.sysconfig as du_sysconfig

from typing import Dict, List

if sys.version_info[:2] < (3, 10):
    from distutils.command import build
    from distutils.dir_util import mkpath
else:
    from setuptools.command import build

from setuptools.command import build_ext

logging.basicConfig(
    format='%(levelname)s:%(funcName)s:%(message)s',
    stream=sys.stdout,
    level=logging.DEBUG,
)
log = logging.getLogger('setup')

requires_list = []


def _get_additional_includes():
    if os.name == 'nt':
        globmask = os.path.join(
            'C:',
            os.sep,
            'Program Files*',
            '*Visual*',
            'VC',
            'include',
        )
        err = glob.glob(globmask)
    else:
        if platform.system() == "Darwin":
            sdk_path = (
                subprocess.check_output(['xcrun', '--show-sdk-path'])
                .decode()
                .strip()
            )
            return [os.path.join(sdk_path, 'usr', 'include')]

        cpp = shlex.split(os.environ.get('CPP', 'cpp'))
        cflags = os.environ.get("CFLAGS")
        if cflags is not None:
            cpp += cflags.split()
        pid = subprocess.Popen(
            cpp + ['-Wp,-v', '-'],
            stdin=open(os.devnull, 'r'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, err = pid.communicate()
        err = [
            line.lstrip()
            for line in err.decode('utf8').split('\n')
            if line and line.startswith(' /')
        ]

    log.debug('additional includes:\n%s', err)
    return err


def openssl_version(
    ossldir: str, req_ver: int, required: bool = False
):
    """
    Compare version of the installed OpenSSL with the maximum required version.

    :param ossldir: the directory where OpenSSL is installed
    :param req_ver: required version as integer (e.g. 0x10100000)
    :param required: whether we want bigger-or-equal or less-than
    :return: Boolean indicating whether the satisfying version of
             OpenSSL has been installed.
    """
    ver = None
    try:
        if sys.platform == 'win32':
            found_lib = glob.glob(
                os.path.join(
                    os.environ.get('OPENSSL_PATH'), 'libcrypto*.dll'
                )
            )[0]
            crypt_lib = ctypes.WinDLL(found_lib)
        else:
            crypt_lib = ctypes.cdll.LoadLibrary("libssl.so")
        log.info(f'crypt_lib = {crypt_lib}')
    except (AttributeError, FileNotFoundError):
        ver = None
        file = os.path.join(
            ossldir, 'include', 'openssl', 'opensslv.h'
        )

        with open(file) as origin_file:
            for line in origin_file:
                m = re.match(
                    r'^# *define  *OPENSSL_VERSION_NUMBER  *(0x[0-9a-fA-F]*)',
                    line,
                )
                if m:
                    log.debug(
                        'found version number: %s\n', m.group(1)
                    )
                    ver = int(m.group(1), base=16)
                    break

        if ver is None:
            raise OSError('Unknown format of file %s\n' % file)
    else:
        try:
            ver = crypt_lib.OpenSSL_version_num()
        except OSError:
            pass
    log.info(f'ctypes: ver = {ver:#0X}')

    if required:
        return ver >= req_ver
    else:
        return ver < req_ver


class _M2CryptoBuildExt(build_ext.build_ext):
    """Enable swig_opts to inherit any include_dirs settings made elsewhere."""

    def initialize_options(self):
        """Overload to enable custom openssl settings to be picked up."""
        build_ext.build_ext.initialize_options(self)

    def finalize_options(self) -> None:
        """Append custom openssl include file and library linking options."""
        build_ext.build_ext.finalize_options(self)
        self.openssl_path = os.environ.get('OPENSSL_PATH', None)
        self.bundledlls = os.environ.get('BUNDLEDLLS', None)

        self.libraries = ['ssl', 'crypto']
        if sys.platform == 'win32':
            self.libraries = ['ssleay32', 'libeay32']
            if self.openssl_path and openssl_version(
                self.openssl_path, 0x10100000, True
            ):
                self.libraries = ['libssl', 'libcrypto']
                self.swig_opts.append('-D_WIN32')
                # Swig doesn't know the version of MSVC, which causes
                # errors in e_os2.h trying to import stdint.h. Since
                # python 2.7 is intimately tied to MSVC 2008, it's
                # harmless for now to define this. Will come back to
                # this shortly to come up with a better fix.
                self.swig_opts.append('-D_MSC_VER=1500')

        if os.path.exists(
            os.path.join(os.curdir, 'system_shadowing')
        ):
            self.swig_opts.append('-Isystem_shadowing')

        log.debug('self.openssl_path = %s', self.openssl_path)
        log.debug('self.bundledlls = %s', self.bundledlls)

        # swig seems to need the default header file directories
        self.swig_opts.extend(
            ['-I%s' % i for i in _get_additional_includes()]
        )

        log.debug('self.include_dirs = %s', self.include_dirs)
        log.debug('self.library_dirs = %s', self.library_dirs)

        if self.openssl_path is not None:
            log.debug('self.openssl_path = %s', self.openssl_path)
            openssl_library_dir = os.path.join(
                self.openssl_path, 'lib'
            )
            openssl_include_dir = os.path.join(
                self.openssl_path, 'include'
            )

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
            if mach in ('arm64_be'):
                self.swig_opts.append('-D__AARCH64EB__')

        self.swig_opts.extend(['-I%s' % i for i in self.include_dirs])

        if sys.platform != 'win32':
            # generate src/SWIG/x509_v_flag.h to overcome weaknesses of swig
            # https://todo.sr.ht/~mcepl/m2crypto/298
            with open(
                "src/SWIG/x509_v_flag.h", "w", encoding="utf-8"
            ) as x509_v_h:
                cmd = [shutil.which(os.environ.get('CC', 'gcc'))]
                cflags = os.environ.get("CFLAGS")
                if cflags is not None:
                    cmd += cflags.split()
                cmd += [
                    "-E",
                    "-fdirectives-only",
                    "-include",
                    "openssl/x509_vfy.h",
                    "-",
                ]
                pid = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                xout, xerr = pid.communicate("\n")
                if pid.returncode == 0:
                    for line in xout.split("\n"):
                        if line and line.find('X509_V_FLAG') > -1:
                            print(line, file=x509_v_h)
                else:
                    raise RuntimeError(
                        f"gcc -E ended with return code {pid.returncode}"
                    )

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
        if self.openssl_path is None:
            self.swig_opts.append('-I/usr/include/openssl')
        else:
            self.swig_opts.append(
                '-I' + os.path.join(openssl_include_dir, 'openssl')
            )

        if platform.system() == "Darwin":
            self.swig_opts.append("-cpperraswarn")

        self.swig_opts.append('-includeall')
        self.swig_opts.append('-builtin')

        build_dir = os.path.join(self.build_lib, 'M2Crypto')
        os.makedirs(build_dir, exist_ok=True)

        # These two lines are a workaround for
        # http://bugs.python.org/issue2624 , hard-coding that we are only
        # building a single extension with a known path; a proper patch to
        # distutils would be in the run phase, when extension name and path are
        # known.
        self.swig_opts.extend(['-outdir', build_dir])
        self.include_dirs.append(
            os.path.join(os.getcwd(), 'src', 'SWIG')
        )

        if sys.platform == 'cygwin' and self.openssl_path is not None:
            # Cygwin SHOULD work (there's code in distutils), but
            # if one first starts a Windows command prompt, then bash,
            # the distutils code does not seem to work. If you start
            # Cygwin directly, then it would work even without this change.
            # Someday distutils will be fixed and this won't be needed.
            self.library_dirs += [
                os.path.join(self.openssl_path, 'bin')
            ]

        os.makedirs(
            os.path.join(self.build_lib, 'M2Crypto'), exist_ok=True
        )

    def run(self):
        """
        On Win32 platforms include the openssl dll's in the binary packages
        """

        # Win32 bdist builds must set OPENSSL_PATH before the builds step.
        if self.bundledlls is None:
            build_ext.build_ext.run(self)
            return

        # self.bundledlls is set
        if sys.platform == 'win32':
            ver_part = ''
            if self.openssl_path and openssl_version(
                self.openssl_path, 0x10100000, True
            ):
                ver_part += '-1_1'
            if sys.maxsize > 2**32:
                ver_part += '-x64'
            search = list(self.library_dirs)
            if self.openssl_path:
                search = search + [
                    self.openssl_path,
                    os.path.join(self.openssl_path, 'bin'),
                ]
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
                raise Exception(
                    "Libs not found {}".format(','.join(libs))
                )
        build_ext.build_ext.run(self)


x_comp_args = set()

# We take care of deprecated functions in OpenSSL with our code, no need
# to spam compiler output with it.
if sys.platform == 'win32':
    x_comp_args.update(['-DTHREADING', '-D_CRT_SECURE_NO_WARNINGS'])
else:
    x_comp_args.update(
        ['-DTHREADING', '-Wno-deprecated-declarations']
    )

m2crypto = setuptools.Extension(
    name='M2Crypto._m2crypto',
    sources=['src/SWIG/_m2crypto.i'],
    extra_compile_args=list(x_comp_args),
    # Uncomment to build Universal Mac binaries
    # extra_link_args =
    #     ['-Wl,-search_paths_first'],
)


setuptools.setup(
    ext_modules=[m2crypto], cmdclass={'build_ext': _M2CryptoBuildExt}
)
