/* Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved. */
/* $Id: _lib.i,v 1.3 2004/03/21 12:35:24 ngps Exp $ */

%{
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <ceval.h>

/* Blob interface. Deprecated. */

Blob *blob_new(int len, const char *errmsg) {
    Blob *blob=(Blob *)malloc(sizeof(Blob));
    if (!blob) {
        PyErr_SetString(PyExc_MemoryError, errmsg);
        return NULL;
    }
    if ((blob->data=(unsigned char *)malloc(len))==NULL) {
        free(blob);
        PyErr_SetString(PyExc_MemoryError, errmsg);
        return NULL;
    }
    blob->len=len;
    return blob;
}

Blob *blob_copy(Blob *from, const char *errmsg) {
    Blob *blob=blob_new(from->len, errmsg);
    if (!blob) {
        PyErr_SetString(PyExc_MemoryError, errmsg);
        return NULL;
    }
    memcpy(blob->data, from->data, from->len);
    return blob;
}

void blob_free(Blob *blob) {
    free(blob->data);
    free(blob);
}


/* Bignum routines that aren't not numerous enough to 
warrant a separate file. */

PyObject *bn_to_mpi(BIGNUM *bn) {
    int len;
    unsigned char *mpi;
    PyObject *pyo;  

    len = BN_bn2mpi(bn, NULL);
    if ((mpi=(unsigned char *)malloc(len))==NULL) {
        PyErr_SetString(PyExc_RuntimeError, 
            ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    len=BN_bn2mpi(bn, mpi);
    pyo=PyString_FromStringAndSize((const char *)mpi, len);
    free(mpi);
    return pyo;
}

BIGNUM *mpi_to_bn(Blob *mpi) {
    return BN_mpi2bn(mpi->data, mpi->len, NULL);
}

BIGNUM *bin_to_bn(Blob *bin) {
    return BN_bin2bn(bin->data, bin->len, NULL);
}


/* C callbacks invoked by OpenSSL; these in turn call back into 
Python. */

int ssl_verify_callback(int ok, X509_STORE_CTX *ctx) {
    PyObject *argv, *ret, *_x509, *_ssl_ctx;
    X509 *x509;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int errnum, errdepth, cret;
    PyThreadState *_save;

    x509 = X509_STORE_CTX_get_current_cert(ctx);
    errnum = X509_STORE_CTX_get_error(ctx);
    errdepth = X509_STORE_CTX_get_error_depth(ctx);

    ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
    ssl_ctx = SSL_get_SSL_CTX(ssl);

    _x509 = SWIG_NewPointerObj((void *)x509, SWIGTYPE_p_X509, 0);
    _ssl_ctx = SWIG_NewPointerObj((void *)ssl_ctx, SWIGTYPE_p_SSL_CTX, 0);
    argv = Py_BuildValue("(OOiii)", _ssl_ctx, _x509, errnum, errdepth, ok);

    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    ret = PyEval_CallObject(ssl_verify_cb_func, argv);
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }

    /* XXX if the callback raised a Python exception, what is ret? */
    cret = (int)PyInt_AsLong(ret);
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    Py_XDECREF(_ssl_ctx);
    Py_XDECREF(_x509);

    if (cret) 
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
    return cret;
}

void ssl_info_callback(const SSL *s, int where, int ret) {
    PyObject *argv, *retval, *_SSL;
    PyThreadState *_save;

    _SSL = SWIG_NewPointerObj((void *)s, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(iiO)", where, ret, _SSL);
    
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data((SSL *)s);
        PyEval_RestoreThread(_save);
    }
    retval = PyEval_CallObject(ssl_info_cb_func, argv);
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data((SSL *)s, _save);
    }

    Py_XDECREF(retval);
    Py_XDECREF(argv);
    Py_XDECREF(_SSL);
}

DH *ssl_set_tmp_dh_callback(SSL *ssl, int is_export, int keylength) {
    PyObject *argv, *ret, *_ssl;
    DH *dh;
    PyThreadState *_save;

    _ssl = SWIG_NewPointerObj((void *)ssl, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(Oii)", _ssl, is_export, keylength);

    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    ret = PyEval_CallObject(ssl_set_tmp_dh_cb_func, argv);
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }

    if ((SWIG_ConvertPtr(ret, (void **)&dh, SWIGTYPE_p_DH, SWIG_POINTER_EXCEPTION | 0)) == -1)
      dh = NULL;
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    Py_XDECREF(_ssl);

    return dh;
}

RSA *ssl_set_tmp_rsa_callback(SSL *ssl, int is_export, int keylength) {
    PyObject *argv, *ret, *_ssl;
    RSA *rsa;
    PyThreadState *_save;

    _ssl = SWIG_NewPointerObj((void *)ssl, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(Oii)", _ssl, is_export, keylength);

    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    ret = PyEval_CallObject(ssl_set_tmp_rsa_cb_func, argv);
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }

    if ((SWIG_ConvertPtr(ret, (void **)&rsa, SWIGTYPE_p_RSA, SWIG_POINTER_EXCEPTION | 0)) == -1)
      rsa = NULL;
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    Py_XDECREF(_ssl);

    return rsa;
}

void gen_callback(int p, int n, void *arg) {
    PyObject *argv, *ret, *cbfunc;
 
    cbfunc = (PyObject *)arg;
    argv = Py_BuildValue("(ii)", p, n);
    ret = PyEval_CallObject(cbfunc, argv);
    Py_DECREF(argv);
    Py_XDECREF(ret);
}

int passphrase_callback(char *buf, int num, int v, void *arg) {
    int i, len;
    char *str;
    PyObject *argv, *ret, *cbfunc;

    cbfunc = (PyObject *)arg;
    argv = Py_BuildValue("(i)", v);
    ret = PyEval_CallObject(cbfunc, argv);
    Py_DECREF(argv);
    if (ret == NULL) {
        return -1;
    }
    if (!PyString_Check(ret)) {
        Py_DECREF(ret);
        return -1;
    }
    if ((len = PyString_Size(ret)) > num)
        len = num;
    str = PyString_AsString(ret); 
    for (i = 0; i < len; i++)
        buf[i] = str[i];
    Py_DECREF(ret);
    return len;
}
%}

%inline %{
void lib_init() {
    SSLeay_add_all_algorithms();
    ERR_load_ERR_strings();
}
%}


/* Various useful typemaps. */

%typemap(python, in) Blob * {
    if (!PyString_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected PyString");
        return NULL;
    }
    $1=(Blob *)malloc(sizeof(Blob));
    if (!$1) {
        PyErr_SetString(PyExc_MemoryError, "malloc Blob");
        return NULL;
    }
    $1->data=(unsigned char *)PyString_AsString($input);
    $1->len=PyString_Size($input);
}

%typemap(python, out) Blob * {
    if ($1==NULL) {
        Py_INCREF(Py_None);
        $result=Py_None;
    } else {
        $result=PyString_FromStringAndSize((const char *)$1->data, $1->len);
        free($1->data); free($1);
    }
}

%typemap(python, in) FILE * {
    if (!PyFile_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected PyFile");
        return NULL;
    }
    $1=PyFile_AsFile($input);
}

%typemap(python, in) PyObject *pyfunc {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected PyCallable");
        return NULL;
    }
    $1=$input;
}

%typemap(python, in) PyObject *pyblob {
    if (!PyString_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "expected PyString");
        return NULL;
    }
    $1=$input;
}

%typemap(python, in) PyObject * {
    $1=$input;
}

%typemap(python, out) PyObject * {
    $result=$1;
}

%typemap(python, out) int {
    $result=PyInt_FromLong($1);
    if (PyErr_Occurred()) SWIG_fail;
}

/* Pointer checks. */

%apply Pointer NONNULL { Blob * };


/* A bunch of "straight-thru" functions. */

%name(err_print_errors_fp) extern void ERR_print_errors_fp(FILE *);
%name(err_print_errors) extern void ERR_print_errors(BIO *);
%name(err_get_error) extern unsigned long ERR_get_error(void);
%name(err_lib_error_string) extern const char *ERR_lib_error_string(unsigned long);
%name(err_func_error_string) extern const char *ERR_func_error_string(unsigned long);
%name(err_reason_error_string) extern const char *ERR_reason_error_string(unsigned long);


