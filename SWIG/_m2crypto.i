/* Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved. */
/* $Id: _m2crypto.i,v 1.2 2003/10/26 13:19:14 ngps Exp $ */

%module _m2crypto

%{
static char *RCS_id="$Id: _m2crypto.i,v 1.2 2003/10/26 13:19:14 ngps Exp $";

#include <openssl/err.h>
#include <openssl/rand.h>
#include <_lib.h>

static PyObject *ssl_verify_cb_func;
static PyObject *ssl_info_cb_func;
static PyObject *ssl_info_cb_func;
static PyObject *ssl_set_tmp_dh_cb_func;
static PyObject *ssl_set_tmp_rsa_cb_func;

static int thread_mode = 0;
%}

%include constraints.i
%include _threads.i
%include _lib.i
%include _bio.i
%include _rand.i
%include _evp.i
%include _rc4.i
%include _dh.i
%include _rsa.i
%include _dsa.i
%include _ssl.i
%include _x509.i
%include _asn1.i
%include _pkcs7.i
%include _util.i

#ifdef SWIG_VERSION
%constant int encrypt = 1;
%constant int decrypt = 0;
#endif
  
