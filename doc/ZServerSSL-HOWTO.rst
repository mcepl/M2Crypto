:orphan:

.. _zserverssl-howto:

ZServerSSL-HOWTO
################

:author: Pheng Siong Ng <ngps@post1.com>
:copyright: © 2000, 2001 by Ng Pheng Siong.
:date: 2003-06-22

.. contents::
    :backlinks: entry

.. sectnum::
    :suffix: .

Introduction
============

ZServerSSL adds to Zope's ZServer the following:

-  HTTPS server
-  WebDAV-source-over-HTTPS server

With the HTTPS server, ZServerSSL also provides WebDAV-over-HTTPS and
XMLRPC-over-HTTPS access to Zope.

These instructions apply to both Un\*x and Windows installations of Zope
2.6.1. To avoid cluttering the presentation, Windows pathnames are shown
in Un\*x fashion.

Preparation
===========

#. Download M2Crypto 0.11, contained in the file ``m2crypto-0.11.zip``.
#. Unpack ``m2crypto-0.11.zip``. This will create a directory
   ``m2crypto-0.11``. Henceforth, we refer to this directory as ``$M2``.
#. Install M2Crypto per the instructions in ``$M2/INSTALL``.

The ZServerSSL distribution is in ``$M2/demo/Zope``. We shall refer to
this directory as ``$ZSSL``.

Installation
============

Below, we refer to your Zope top-level directory as ``$ZOPE``.

#. Copy ``$ZSSL/z2s.py`` into ``$ZOPE``.

#. Depending on your operating system, modify ``$ZOPE/start`` or
   ``$ZOPE/start.bat`` to invoke ``$ZOPE/z2s.py``, instead of
   ``$ZOPE/z2.py``. The files ``$ZSSL/starts`` and ``$ZSSL/starts.bat``
   serve as examples.

#. Copy ``$ZSSL/dh1024.pem`` into ``$ZOPE``. This file contains
   Diffie-Hellman parameters for use by the SSL protocol.

#. Copy ``$ZSSL/randpool.dat`` into ``$ZOPE``. This file contains seed
   material for the OpenSSL PRNG. Alternatively, create
   ``$ZOPE/randpool.dat`` thusly::

       $ dd if=/dev/urandom of=randpool.dat bs=1024 count=1

#. Copy ``$ZSSL/ca.pem`` to ``$ZOPE``. This file contains an
   example Certification Authority (CA) certificate. For
   information on operating your own CA, see :ref:`howto-ca` or
   one of numerous similar documents available on the web.

#. Copy ``$ZSSL/server.pem`` to ``$ZOPE``. This file contains an RSA key
   pair and its X.509v3 certificate issued by the above CA. You may also
   create your own key/certificate bundle.

#. Copy ``$ZSSL/ZServer/HTTPS_Server.py`` to ``$ZOPE/ZServer``.

#. Copy ``$ZSSL/ZServer/__init__.py`` to ``$ZOPE/ZServer``. This
   overwrites the existing ``$ZOPE/ZServer/__init__.py``. Alternatively,
   apply the following patch to ``$ZOPE/ZServer/__init__.py``::

       --- __init__.py.org     Sat Jun 21 23:20:41 2003
       +++ __init__.py Tue Jan  7 23:30:53 2003
       @@ -84,6 +84,7 @@
        import asyncore
        from medusa import resolver, logger
        from HTTPServer import zhttp_server, zhttp_handler
       +from HTTPS_Server import zhttps_server, zhttps_handler
        from PCGIServer import PCGIServer
        from FCGIServer import FCGIServer
        from FTPServer import FTPServer

#. Copy ``$ZSSL/ZServer/medusa/https_server.py`` to
   ``$ZOPE/ZServer/medusa``.

#. Stop Zope, if it is running.

#. Start Zope with ZServerSSL thusly::

       ./starts -X -f 9021 -w 9080 -W 9081 -y 9443 -Y 9444

   This starts the following:

   -  an FTP server on port 9021
   -  a HTTP server on port 9080
   -  a WebDAV-source server on port 9081
   -  a HTTPS server on port 9443
   -  a WebDAV-source-over-HTTPS server on port 9444

Testing
=======

Below, we assume your Zope server is running on ``localhost``.

HTTPS
=====

This testing is done with Mozilla 1.1 on FreeBSD.

#. With a browser, connect to https://localhost:9443/. Browse around.
   Check out your browser's HTTPS informational screens.
#. Connect to https://localhost:9443/manage. Verify that you can access
   Zope's management functionality.

WebDAV-over-HTTPS
=================

This testing is done with Cadaver 0.21.0 on FreeBSD.::

    $ cadaver https://localhost:9443/
    WARNING: Untrusted server certificate presented:
    Issued to: M2Crypto, SG
    Issued by: M2Crypto, SG
    Do you wish to accept the certificate? (y/n) y
    dav:/> ls
    Listing collection `/': succeeded.
    Coll:   Channels                               0  Jun 19 00:04
    Coll:   Control_Panel                          0  Jun  6 00:13
    Coll:   Examples                               0  Jun  6 00:12
    Coll:   catalog                                0  Jun 12 11:53
    Coll:   ngps                                   0  Jun 16 15:34
    Coll:   portal                                 0  Jun 21 15:21
    Coll:   skunk                                  0  Jun 18 21:18
    Coll:   temp_folder                            0  Jun 22 17:57
    Coll:   zope                                   0  Jun 20 15:27
            acl_users                              0  Dec 30  1998
            browser_id_manager                     0  Jun  6 00:12
            default.css                         3037  Jun 21 16:38
            error_log                              0  Jun  6 00:12
            index_html                           313  Jun 12 13:36
            portal0                                0  Jun 21 15:21
            session_data_manager                   0  Jun  6 00:12
            standard_error_message              1365  Jan 21  2001
            standard_html_footer                  50  Jun 12 12:30
            standard_html_header                  80  Jan 21  2001
            standard_template.pt                 282  Jun  6 00:12
            zsyncer                                0  Jun 17 15:28
    dav:/> quit
    Connection to `localhost' closed.
    $ 


WebDAV-Source-over-HTTPS
========================

This testing is done with Mozilla 1.1 on FreeBSD.

#. Open the Mozilla Composer window.
#. Click "File", "Open Web Location". A dialog box appears.
#. Enter ``https://localhost:9444/index_html`` for the URL.
#. Select "Open in new Composer window."
#. Click "Open". A new Composer window will open with ``index_html``
   loaded.

Python with M2Crypto
====================

This testing is done with M2Crypto 0.11 and Python 2.2.2 on FreeBSD.

HTTPS
=====

::

    >>> from M2Crypto import Rand, SSL, m2urllib
    >>> url = m2urllib.FancyURLopener()
    >>> url.addheader('Connection', 'close')
    >>> u = url.open('https://127.0.0.1:9443/')
    send: 'GET / HTTP/1.1\r\nHost: 127.0.0.1:9443\r\nAccept-Encoding: identity\r\nUser-agent: Python-urllib/1.15\r\nConnection: close\r\n\r\n'
    reply: 'HTTP/1.1 200 OK\r\n'
    header: Server: ZServerSSL/0.11
    header: Date: Sun, 22 Jun 2003 13:42:34 GMT
    header: Connection: close
    header: Content-Type: text/html
    header: Etag: 
    header: Content-Length: 535
    >>> while 1:
    ...     data = u.read()
    ...     if not data: break
    ...     print(data)
    ... 

::

    <html><head>
    <base href="https://127.0.0.1:9443/" />
    <title>Zope</title></head><body bgcolor="#FFFFFF">

    <h1>NgPS Desktop Portal</h1>

    &nbsp;&nbsp;So many hacks.<br>
    &nbsp;&nbsp;So little time.<br>

    <h2>Link Farm</h2>
    <ul>
    <li><a href="http://localhost:8080/portal">Portal</a></li>
    <li><a href="http://localhost/">Local Apache Home Page</a></li>
    </ul>

    <hr><a href="http://www.zope.org/Credits" target="_top"><img src="https://127.0.0.1:9443/p_/ZopeButton" width="115" height="50" border="0" alt="Powered by Zope" /></a></body></html>

::

    >>> u.close()
    >>> 

XMLRPC-over-HTTPS
=================

::

    >>> from M2Crypto.m2xmlrpclib import Server, SSL_Transport
    >>> zs = Server('https://127.0.0.1:9443/', SSL_Transport())
    >>> print(zs.propertyMap())
    [{'type': 'string', 'id': 'title', 'mode': 'w'}]
    >>> 

Conclusion
==========

Well, it works! ;-)
