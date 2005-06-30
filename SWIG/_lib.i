/* Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
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


/* C callbacks invoked by OpenSSL; these in turn call back into 
Python. */

int ssl_verify_callback(int ok, X509_STORE_CTX *ctx) {
    PyObject *argv, *ret;
    PyObject *_x509_store_ctx_swigptr=0, *_x509_store_ctx_obj=0, *_x509_store_ctx_inst=0, *_klass=0;
    PyObject *_x509=0, *_ssl_ctx=0;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    X509 *x509;
    int errnum, errdepth;
    int cret;
    int new_style_callback = 0, warning_raised_exception=0;
#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_STATE gilstate;
#else
    PyThreadState *_save;
#endif

    ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
    	
#if PY_VERSION_HEX >= 0x20300F0
    gilstate = PyGILState_Ensure();
#else
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    if (PyErr_Warn(PyExc_DeprecationWarning, "This should not work. If it does for you, let me know. --Heikki Toivonen")) {
        if (thread_mode) {
            _save = PyEval_SaveThread();
            SSL_set_app_data(ssl, _save);
        }
        return 0;
    }
#endif

    if (PyMethod_Check(ssl_verify_cb_func)) {
        PyObject *func;
        PyCodeObject *code;
        func = PyMethod_Function(ssl_verify_cb_func);
        code = (PyCodeObject *) PyFunction_GetCode(func);
        if (code && code->co_argcount == 3) { /* XXX Python internals */
            new_style_callback = 1;
        }
    } else if (PyFunction_Check(ssl_verify_cb_func)) {
        PyCodeObject *code = (PyCodeObject *) PyFunction_GetCode(ssl_verify_cb_func);
        if (code && code->co_argcount == 2) { /* XXX Python internals */
            new_style_callback = 1;
        }    
    } else {
        /* XXX There are lots of other callable types, but we will assume
         * XXX that any other type of callable uses the new style callback,
         * XXX although this is not entirely safe assumption.
         */
        new_style_callback = 1;
    }
    
    if (new_style_callback) {
        PyObject *x509mod = PyDict_GetItemString(PyImport_GetModuleDict(), "M2Crypto.X509");
        _klass = PyObject_GetAttrString(x509mod, "X509_Store_Context");
    
        _x509_store_ctx_swigptr = SWIG_NewPointerObj((void *)ctx, SWIGTYPE_p_X509_STORE_CTX, 0);
        _x509_store_ctx_obj = Py_BuildValue("(Oi)", _x509_store_ctx_swigptr, 0);
        _x509_store_ctx_inst = PyInstance_New(_klass, _x509_store_ctx_obj, NULL);
        argv = Py_BuildValue("(iO)", ok, _x509_store_ctx_inst);
    } else {
        if (PyErr_Warn(PyExc_DeprecationWarning, "Old style callback, use cb_func(ok, store) instead")) {
            warning_raised_exception = 1;
        }
       
        x509 = X509_STORE_CTX_get_current_cert(ctx);
        errnum = X509_STORE_CTX_get_error(ctx);
        errdepth = X509_STORE_CTX_get_error_depth(ctx);
    
        ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
        ssl_ctx = SSL_get_SSL_CTX(ssl);
    
        _x509 = SWIG_NewPointerObj((void *)x509, SWIGTYPE_p_X509, 0);
        _ssl_ctx = SWIG_NewPointerObj((void *)ssl_ctx, SWIGTYPE_p_SSL_CTX, 0);
        argv = Py_BuildValue("(OOiii)", _ssl_ctx, _x509, errnum, errdepth, ok);    
    }

    if (!warning_raised_exception) {
        ret = PyEval_CallObject(ssl_verify_cb_func, argv);
    } else {
        ret = 0;
    }

    if (!ret) {
        /* Got an exception in PyEval_CallObject(), let's fail verification
         * to be safe.
         */
        cret = 0;   
    } else {
        cret = (int)PyInt_AsLong(ret);
    }
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    if (new_style_callback) {
        Py_XDECREF(_x509_store_ctx_inst);
        Py_XDECREF(_x509_store_ctx_obj);
        Py_XDECREF(_x509_store_ctx_swigptr);
        Py_XDECREF(_klass);
    } else {
        Py_XDECREF(_x509);
        Py_XDECREF(_ssl_ctx);
    }

#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_Release(gilstate);
#else
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
#endif

    return cret;
}

void ssl_info_callback(const SSL *s, int where, int ret) {
    PyObject *argv, *retval, *_SSL;
#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_STATE gilstate;
#else
    PyThreadState *_save;
#endif

#if PY_VERSION_HEX >= 0x20300F0
    gilstate = PyGILState_Ensure();
#else
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data((SSL *)s);
        PyEval_RestoreThread(_save);
    }
#endif

    _SSL = SWIG_NewPointerObj((void *)s, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(iiO)", where, ret, _SSL);
    
    retval = PyEval_CallObject(ssl_info_cb_func, argv);

    Py_XDECREF(retval);
    Py_XDECREF(argv);
    Py_XDECREF(_SSL);

#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_Release(gilstate);
#else
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data((SSL *)s, _save);
    }
#endif
}

DH *ssl_set_tmp_dh_callback(SSL *ssl, int is_export, int keylength) {
    PyObject *argv, *ret, *_ssl;
    DH *dh;
#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_STATE gilstate;
#else
    PyThreadState *_save;
#endif

#if PY_VERSION_HEX >= 0x20300F0
    gilstate = PyGILState_Ensure();
#else
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
#endif

    _ssl = SWIG_NewPointerObj((void *)ssl, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(Oii)", _ssl, is_export, keylength);

    ret = PyEval_CallObject(ssl_set_tmp_dh_cb_func, argv);

    if ((SWIG_ConvertPtr(ret, (void **)&dh, SWIGTYPE_p_DH, SWIG_POINTER_EXCEPTION | 0)) == -1)
      dh = NULL;
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    Py_XDECREF(_ssl);

#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_Release(gilstate);
#else
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
#endif

    return dh;
}

RSA *ssl_set_tmp_rsa_callback(SSL *ssl, int is_export, int keylength) {
    PyObject *argv, *ret, *_ssl;
    RSA *rsa;
#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_STATE gilstate;
#else
    PyThreadState *_save;
#endif

#if PY_VERSION_HEX >= 0x20300F0
    gilstate = PyGILState_Ensure();
#else
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
#endif

    _ssl = SWIG_NewPointerObj((void *)ssl, SWIGTYPE_p_SSL, 0);
    argv = Py_BuildValue("(Oii)", _ssl, is_export, keylength);

    ret = PyEval_CallObject(ssl_set_tmp_rsa_cb_func, argv);

    if ((SWIG_ConvertPtr(ret, (void **)&rsa, SWIGTYPE_p_RSA, SWIG_POINTER_EXCEPTION | 0)) == -1)
      rsa = NULL;
    Py_XDECREF(ret);
    Py_XDECREF(argv);
    Py_XDECREF(_ssl);

#if PY_VERSION_HEX >= 0x20300F0
    PyGILState_Release(gilstate);
#else
    if (thread_mode) {
        _save = PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
#endif

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

BIGNUM *mpi_to_bn(PyObject *value) {
    const void *vbuf;
    int vlen;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    vlen = PyString_Size(value);
    vbuf = (const void *)PyString_AsString(value);
#endif
    return BN_mpi2bn(vbuf, vlen, NULL);
}

PyObject *bn_to_bin(BIGNUM *bn) {
    int len;
    unsigned char *bin;
    PyObject *pyo;  

    len = BN_num_bytes(bn);
    if ((bin=(unsigned char *)malloc(len))==NULL) {
      PyErr_SetString(PyExc_MemoryError, "Cannot malloc buffer for conversion.");
      return NULL;
    }
    BN_bn2bin(bn, bin);
    pyo=PyString_FromStringAndSize((const char *)bin, len);
    free(bin);
    return pyo;
}

BIGNUM *bin_to_bn(PyObject *value) {
    const void *vbuf;
    int vlen;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    vlen = PyString_Size(value);
    vbuf = (const void *)PyString_AsString(value);
#endif
    return BN_bin2bn(vbuf, vlen, NULL);
}

BIGNUM *hex_to_bn(PyObject *value) {
    const void *vbuf;
    int vlen;
    BIGNUM *bn;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    vbuf = (const void *)PyString_AsString(value);
#endif
    if ((bn=BN_new())==NULL) {
      PyErr_SetString(PyExc_MemoryError, "Unable to malloc a BIGNUM.");
      return NULL;
    }
    if ((BN_hex2bn(&bn, (const char *)vbuf) <= 0)) {
      PyErr_SetString(PyExc_RuntimeError, 
            ERR_error_string(ERR_get_error(), NULL));
      free(bn);
      return NULL;
    }
    return bn;
}

BIGNUM *dec_to_bn(PyObject *value) {
    const void *vbuf;
    int vlen;
    BIGNUM *bn;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    vbuf = (const void *)PyString_AsString(value);
#endif
    if ((bn=BN_new())==NULL) {
      PyErr_SetString(PyExc_MemoryError, "Unable to malloc a BIGNUM.");
      return NULL;
    }
    if ((BN_dec2bn(&bn, (const char *)vbuf) <= 0)) {
      PyErr_SetString(PyExc_RuntimeError, 
            ERR_error_string(ERR_get_error(), NULL));
      free(bn);
      return NULL;
    }
    return bn;
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


