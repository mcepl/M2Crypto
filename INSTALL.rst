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

This assumes OpenSSL is installed in /usr. You can provide an alternate
OpenSSL prefix location with --openssl option to build\_ext command.
Other commands accept standard options if you need them.

Some distributions, like Fedora Core, package OpenSSL headers in a
different location from OpenSSL itself. In that case you need to tell
``build`` the additional include location with -I option.

Differences when installing on Windows
--------------------------------------

(needs updating)

Before building from source, you need to install OpenSSL's include
files, import libraries and DLLs. By default setup.py assumes that
OpenSSL include files are in ``c:\pkg\openssl\include``, and the import
libraries in ``c:\pkg\openssl\lib``. As with other platforms, you can
specify a different OpenSSL location with --openssl option to
``build\_ext`` (or ``build``) command.

Using OpenSSL 0.9.8 on Windows requires Python be built with applink.c
(add an include statement in python.c). This is not a requirement for
Linux or MacOSX. (applink.c is provided by OpenSSL.)

MSVC++ ~\ :sub:`:sub:`:sub:`~```

setup.py is already configured to work with MSVC++ by default.

With MSVC++, the OpenSSL DLLs, as built, are named ``libeay32.dll`` and
``ssleay32.dll``. Install these somewhere on your PATH; for example in
``c:\bin``, together with ``openssl.exe``.

For MSVC++, the import libraries, as built by OpenSSL, are named
``libeay32.lib`` and ``ssleay32.lib``.

MINGW :sub:`:sub:`:sub:`~```

.. NOTE:: The following instructions for building M2Crypto with MINGW
    are from M2Crypto 0.12. These instructions should continue to work
    for this release, although I have not tested them.

Read Sebastien Sauvage's webpage::

     http://sebsauvage.net/python/mingw.html

For mingw32, the OpenSSL import libraries are named ``libeay32.a`` and
``libssl32.a``. You may need to edit setup.py file for these.

You'll also need to create ``libpython2[123].a``, depending on your
version of Python.

OpenSSL DLLs for mingw32 are named ``libeay32.dll`` and
``libssl32.dll``. Install these somewhere on your PATH; for example in
``c:\bin``, together with ``openssl.exe``.

Build M2Crypto::

    python setup.py build -cmingw32
    python setup.py install

BC++ :sub:`:sub:`~``\ ~

.. NOTE:: The following instructions for building M2Crypto with MSVC++
    6.0 and BC++ 5.5 free compiler suite are from M2Crypto 0.10. These
    instructions should continue to work for this release, although
    I have not tested them.

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
    $ LDFLAGS="-L$(brew --prefix openssl)/lib" 
    CFLAGS="-I$(brew --prefix openssl)/include" \
    SWIG_FEATURES="-I$(brew --prefix openssl)/include" \
    pip install m2crypto

.. _`since 10.11`:
    https://gitlab.com/m2crypto/m2crypto/merge_requests/7#note_2581821
