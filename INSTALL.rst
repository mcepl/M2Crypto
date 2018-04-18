Installing M2Crypto
===================

.. contents::

Pre-requisites
--------------

The following software packages are pre-requisites:

-  Python 2.6 or newer
-  OpenSSL 1.0.1e or newer
-  Python 2.6 platforms require the Python package unittest2 to be
   installed

For further development you need (aside from the normal development
environment, C compiler, header files for OpenSSL, etc.) also:

-  SWIG 2.0.4 or newer

Debian
~~~~~~

For Py2 & Py3 support install::

    sudo apt-get install build-essential python3-dev python-dev libssl-dev swig


Installing on Unix-like systems, including Cygwin
-------------------------------------------------

(not tested and most likely obsolete, updated information for building
with Cygwin are welcome).::

    $ tar zxf m2crypto-<version>.tar.gz
    $ cd m2crypto-<version>
    $ python setup.py build
    $ python setup.py install

If you have installed setuptools you can also optionally run tests like
this:::

    $ python setup.py test

This assumes OpenSSL is installed in ``/usr``. You can provide an
alternate OpenSSL prefix location with --openssl option to
``build\_ext`` (or ``build``) command. So, for example, if you
build your local version of OpenSSL and install it with
``/usr/local`` prefix (your includes are in
``/usr/local/include/openssl`` and libs in ``/usr/local/lib``),
then you would add ``--openssl=/usr/local`` to your ``build``
command.


Differences when installing on Windows
--------------------------------------

(Python 2.6 is not supported on Windows anymore, please, just 
update to 2.7 if you want to stay on Python 2)

(needs updating)

Before building from source, you need to install OpenSSL's include
files, import libraries and DLLs. OpenSSL 1.1.0 and on are installed
by default in ``%ProgramFiles(86)%\OpenSSL`` (32-bit), or
in ``%ProgramW6432%\OpenSSL`` (64-bit), or as a last resort, in
``%ProgramFiles%\OpenSSL``. setup.py will look in those locations.
OpenSSL before 1.1.0 doesn't have a default install location, so
you have to specify its install location explicitely.

As with other platforms, you can specify a OpenSSL location with
--openssl option to ``build\_ext`` (or ``build``) command. For
example, ``--openssl=c:\pkg\openssl`` would specify that the OpenSSL
include files can be found in ``c:\pkg\openssl\include`` and the
librariesin ``c:\pkg\openssl\lib``.

The '--openssl' option will configure swig and the compiler to look in the
default locations for headers and libraries. If your OpenSSL is installed in a
or you want to modify the default options run the build_ext step with normal
distutils options: `--swig-opts`, `--include-dirs`, `--library-dirs`, and
`--libraries`.

MSVC++ ~\ :sub:`:sub:`:sub:`~```

setup.py is already configured to work with MSVC++ by default.

With MSVC++, the OpenSSL pre 1.1.0 DLLs, as built, are named
``libeay32.dll`` and ``ssleay32.dll``. The OpenSSL 1.1.x DLLs are
named ``libcrypto-1_1.dll`` and ``libssl-1_1.dll``.  Install these
somewhere on your PATH; for example in ``c:\bin``, together with
``openssl.exe``.

For MSVC++, the import libraries, as built by OpenSSL pre 1.1.0, are
named ``libeay32.lib`` and ``ssleay32.lib``.  The OpenSSL 1.1.x import
libraries are named ``libcrypto.lib`` and ``libssl.lib``.

MINGW :sub:`:sub:`:sub:`~```

.. NOTE:: The following instructions for building M2Crypto with MINGW
    are from M2Crypto 0.12. These instructions should continue to work
    for this release, although I have not tested them.

Read Sebastien Sauvage's webpage::

     http://sebsauvage.net/python/mingw.html

For mingw32, the OpenSSL pre 1.1.0 import libraries are named
``libeay32.dll.a`` and ``libssl32.dll.a``. You may need to edit
setup.py file for these.

You'll also need to create ``libpython2[123].a``, depending on your
version of Python.

OpenSSL pre 1.1.0 DLLs for mingw32 are named ``libeay32.dll`` and
``libssl32.dll``. OpenSSL 1.1.x DLLs are named ``libcrypto-1_1.dll``
and ``libssl-1_1.dll``. Install these somewhere on your PATH; for
example in ``c:\bin``, together with ``openssl.exe``.

Build M2Crypto::

    python setup.py build -cmingw32
    python setup.py install

BC++ :sub:`:sub:`~``\ ~

.. NOTE:: The following instructions for building M2Crypto with MSVC++
    6.0 and BC++ 5.5 free compiler suite are from M2Crypto 0.10. These
    instructions should continue to work for this release, although
    I have not tested them.

.. NOTE:: OpenSSL 1.1.x doesn't support BC++.

For BC++ these files are created from the MSVC++-built ones using the
tool ``coff2omf.exe``. I call them ``libeay32_bc.lib`` and
``ssleay32_bc.lib``, respectively. You will need to edit setup.py file
for these.

You'll also need Python's import library, e.g., ``python22.lib``, to be
the BC++-compatible version; i.e., create ``python22_bc.lib`` from
``python22.lib``, save a copy of ``python22.lib`` (as
``python22_vc.lib``, say), then rename ``python22_bc.lib`` to
``python22.lib``.

Now you are ready to build M2Crypto. Do one of the following::

    python setup.py build
    python setup.py build -cbcpp

Then,::

    python setup.py install

MacOSX
------

Apple does not provide on more recent versions of Mac OS X (at least
certainly `since 10.11`_) any version of OpenSSL, so it is necessary to
use ``brew`` or similar packaging systems to install third party
packages. A Mac OS X users suggested, that this series of commands gave
him a working copy of M2Crypto on his system::

    $ brew install openssl && brew install swig
    $ brew --prefix openssl
    /usr/local/opt/openssl
    $ LDFLAGS="-L$(brew --prefix openssl)/lib" \
    CFLAGS="-I$(brew --prefix openssl)/include" \
    SWIG_FEATURES="-I$(brew --prefix openssl)/include" \
    pip install m2crypto

.. _`since 10.11`:
    https://gitlab.com/m2crypto/m2crypto/merge_requests/7#note_2581821
