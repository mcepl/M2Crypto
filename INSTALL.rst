Installing M2Crypto
===================

.. contents::

Pre-requisites
--------------

The following is required to *use* M2Crypto (once installed):

-  ``Python 3.6`` or newer
-  ``OpenSSL 1.1.1t`` or newer

<!-- alpine/32bit OpenSSL 3.3.1, swig 4.2.1, Python 3.12.3
fedora OpenSSL 3.2.1, swig 4.2.1, Python 3.12.3
rawhide OpenSSL 3.2.2, swig 4.2.1, Python 3.13.0~b3
leap OpenSSL 3.1.4, swig 4.1.1, Python 3.6.15
tumbleweed OpenSSL 3.1.4, swig 4.2.1, Python 3.11.9
python3 OpenSSL 3.0.13, swig 4.1.0, Python 3.11.2
python3-32bit OpenSSL 3.0.13, swig 4.1.0, Python 3.11.2
python39 OpenSSL 3.0.13, swig 4.1.0, Python 3.11.2
windows OPenSSL 1.1.1w, swig 4.1.1, Python 3.10.* -->

To *install* M2Crypto, you must be able to compile and link C sources
against Python and OpenSSL headers/libraries. For example on a Debian-based
system the following packages are needed:

- ``build-essential``
- ``python3-dev`` and/or ``python-dev``
- ``libssl-dev``
- ``swig 4.1.0`` or newer (for compatibility with Python 3.12, for
  older Pythons the default platform swig should be enough).

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

    $ python -munittest discover -v tests

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

Binary wheels for many Windows conifgurations are available on
PyPI. Try selecting a version, selecting a job that matches your
Python version, then going to the "Artifacts" tab and downloading
an installer.

1. Install the latest `Build Tools for Visual Studio 2019`.
   See https://visualstudio.microsoft.com/downloads/ under "All
   Downloads" -> "Tools for Visual Studio 2019".
2. In the installer, select "C++ Build Tools", install, and
   reboot if necessary.
3. Install the latest full (not `Light`) `OpenSSL`
   for your architecture (`Win64`/`Win32`). Current
   version as of this writing is `1.1.1d`. Make note
   of the directory to which you install `OpenSSL`.
   https://slproweb.com/products/Win32OpenSSL.html
4. In `PowerShell`, install the `Chocolatey` package manager. I used this command from their website:
   `Set-ExecutionPolicy Bypass -Scope Process -Force;
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))`
5. Install `swig` with `Chocolatey` (in `PowerShell`). `choco install -r -y swig`
6. Install the `pywin32` dependency. Run `pip install
   pywin32`. If you have problems, try first running `pip
   install wheel`. To get `pip` to target a specific Python
   installation, try launching it using `py -[version] -m pip
   install [module]`. Note: you may need to use an elevated
   (administrator) `PowerShell` to install Python modules.
7. Get the latest `m2crypto` code. If you have `git` installed,
   run `git clone https://git.sr.ht/~mcepl/m2crypto`. Otherwise,
   download and extract the code from SourceHut:
   https://git.sr.ht/~mcepl/m2crypto/archive/master.tar.gz
8. Use `cd` to change into the directory `m2crypto` was cloned/extracted to.
9. Assuming `python` launches your desired Python interpreter
   version, run `python setup.py build --openssl="C:\Program
   Files\OpenSSL-Win64" --bundledlls`, replacing `C:\Program
   Files\OpenSSL-Win64` with the directory to which you installed
   `OpenSSL`. (On some systems you can use the `py` launcher
   to specify a Python version to use, run `py -h` for more
   information.)
10. Generate the installable files. `python.exe setup.py
    bdist_wheel bdist_wininst bdist_msi`.
11. Install the module. `cd` into the `dist` directory and run
    `pip install M2Crypto-0.35.2-cp38-cp38-win_amd64.whl`,
    replacing the filename with the generated `.whl` file. If
    you have problems, try first running `pip install wheel`. To
    get `pip` to target a specific Python installation,
    try launching it using `py -[version] -m pip install
    [module]`. Alternatively, you can run the generated `.exe`
    or `.msi` installer. Note: you may need to use an elevated
    (administrator) `PowerShell` to install Python modules.

(needs updating)

.. NOTE:: The following instructions for building M2Crypto with MINGW
    are from M2Crypto 0.12. These instructions should continue to work
    for this release, although I have not tested them.

Read Sebastien Sauvage's webpage::

     http://sebsauvage.net/python/mingw.html

For `setup.py build` you may need to use parameter `-cmingw32`.

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
