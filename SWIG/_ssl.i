/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved. */
/*
** Portions created by Open Source Applications Foundation (OSAF) are
** Copyright (C) 2004-2005 OSAF. All Rights Reserved.
*/
/* $Id$ */

%{
#include <pythread.h>
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
%}

%apply Pointer NONNULL { SSL_CTX * };
%apply Pointer NONNULL { SSL * };
%apply Pointer NONNULL { SSL_CIPHER * };
%apply Pointer NONNULL { STACK * };
%apply Pointer NONNULL { BIO * };
%apply Pointer NONNULL { DH * };
%apply Pointer NONNULL { RSA * };
%apply Pointer NONNULL { PyObject *pyfunc };

%name(ssl_get_version) extern const char *SSL_get_version(CONST SSL *);
%name(ssl_get_error) extern int SSL_get_error(CONST SSL *, int);
%name(ssl_get_state) extern const char *SSL_state_string(const SSL *);
%name(ssl_get_state_v) extern const char *SSL_state_string_long(const SSL *);
%name(ssl_get_alert_type) extern const char *SSL_alert_type_string(int);
%name(ssl_get_alert_type_v) extern const char *SSL_alert_type_string_long(int);
%name(ssl_get_alert_desc) extern const char *SSL_alert_desc_string(int);
%name(ssl_get_alert_desc_v) extern const char *SSL_alert_desc_string_long(int);

%name(sslv2_method) extern SSL_METHOD *SSLv2_method(void);
%name(sslv3_method) extern SSL_METHOD *SSLv3_method(void);
%name(sslv23_method) extern SSL_METHOD *SSLv23_method(void);
%name(tlsv1_method) extern SSL_METHOD *TLSv1_method(void);

%name(ssl_ctx_new) extern SSL_CTX *SSL_CTX_new(SSL_METHOD *);
%name(ssl_ctx_free) extern void SSL_CTX_free(SSL_CTX *);
%name(ssl_ctx_set_verify_depth) extern void SSL_CTX_set_verify_depth(SSL_CTX *, int);
%name(ssl_ctx_get_verify_depth) extern int SSL_CTX_get_verify_depth(CONST SSL_CTX *);
%name(ssl_ctx_get_verify_mode) extern int SSL_CTX_get_verify_mode(CONST SSL_CTX *);
%name(ssl_ctx_set_cipher_list) extern int SSL_CTX_set_cipher_list(SSL_CTX *, const char *);
%name(ssl_ctx_add_session) extern int SSL_CTX_add_session(SSL_CTX *, SSL_SESSION *);
%name(ssl_ctx_remove_session) extern int SSL_CTX_remove_session(SSL_CTX *, SSL_SESSION *);
%name(ssl_ctx_set_session_timeout) extern long SSL_CTX_set_timeout(SSL_CTX *, long);
%name(ssl_ctx_get_session_timeout) extern long SSL_CTX_get_timeout(CONST SSL_CTX *);
%name(ssl_ctx_get_cert_store) extern X509_STORE *SSL_CTX_get_cert_store(CONST SSL_CTX *);

%name(bio_new_ssl) extern BIO *BIO_new_ssl(SSL_CTX *, int);

%name(ssl_new) extern SSL *SSL_new(SSL_CTX *);
%name(ssl_free) extern void SSL_free(SSL *);
%name(ssl_dup) extern SSL *SSL_dup(SSL *);
%name(ssl_set_bio) extern void SSL_set_bio(SSL *, BIO *, BIO *);
%name(ssl_set_accept_state) extern void SSL_set_accept_state(SSL *);
%name(ssl_set_connect_state) extern void SSL_set_connect_state(SSL *);
%name(ssl_get_shutdown) extern int SSL_get_shutdown(CONST SSL *);
%name(ssl_set_shutdown) extern void SSL_set_shutdown(SSL *, int);
%name(ssl_shutdown) extern int SSL_shutdown(SSL *);
%name(ssl_clear) extern int SSL_clear(SSL *);
%name(ssl_do_handshake) extern int SSL_do_handshake(SSL *);
%name(ssl_renegotiate) extern int SSL_renegotiate(SSL *);
%name(ssl_pending) extern int SSL_pending(CONST SSL *);

%name(ssl_get_peer_cert) extern X509 *SSL_get_peer_certificate(CONST SSL *);
%name(ssl_get_current_cipher) extern SSL_CIPHER *SSL_get_current_cipher(CONST SSL *);
%name(ssl_get_verify_mode) extern int SSL_get_verify_mode(CONST SSL *);
%name(ssl_get_verify_depth) extern int SSL_get_verify_depth(CONST SSL *);
%name(ssl_get_verify_result) extern long SSL_get_verify_result(CONST SSL *);
%name(ssl_get_ssl_ctx) extern SSL_CTX *SSL_get_SSL_CTX(CONST SSL *);
%name(ssl_get_default_session_timeout) extern long SSL_get_default_timeout(CONST SSL *);

%name(ssl_set_cipher_list) extern int SSL_set_cipher_list(SSL *, const char *);
%name(ssl_get_cipher_list) extern const char *SSL_get_cipher_list(CONST SSL *, int);

%name(ssl_cipher_get_name) extern const char *SSL_CIPHER_get_name(CONST SSL_CIPHER *);
%name(ssl_cipher_get_version) extern char *SSL_CIPHER_get_version(CONST SSL_CIPHER *);

%name(ssl_get_session) extern SSL_SESSION *SSL_get_session(CONST SSL *);
%name(ssl_get1_session) extern SSL_SESSION *SSL_get1_session(SSL *);
%name(ssl_set_session) extern int SSL_set_session(SSL *, SSL_SESSION *);
%name(ssl_session_free) extern void SSL_SESSION_free(SSL_SESSION *);
%name(ssl_session_print) extern int SSL_SESSION_print(BIO *, CONST SSL_SESSION *);
%name(ssl_session_set_timeout) extern long SSL_SESSION_set_timeout(SSL_SESSION *, long);
%name(ssl_session_get_timeout) extern long SSL_SESSION_get_timeout(CONST SSL_SESSION *);

%constant int ssl_error_none              = SSL_ERROR_NONE;
%constant int ssl_error_ssl               = SSL_ERROR_SSL;
%constant int ssl_error_want_read         = SSL_ERROR_WANT_READ;
%constant int ssl_error_want_write        = SSL_ERROR_WANT_WRITE;
%constant int ssl_error_want_x509_lookup  = SSL_ERROR_WANT_X509_LOOKUP;
%constant int ssl_error_syscall           = SSL_ERROR_SYSCALL;
%constant int ssl_error_zero_return       = SSL_ERROR_ZERO_RETURN;
%constant int ssl_error_want_connect      = SSL_ERROR_WANT_CONNECT;

%constant int SSL_VERIFY_NONE                 = 0x00;
%constant int SSL_VERIFY_PEER                 = 0x01;
%constant int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
%constant int SSL_VERIFY_CLIENT_ONCE          = 0x04;

%constant int SSL_ST_CONNECT                  = 0x1000;
%constant int SSL_ST_ACCEPT                   = 0x2000;
%constant int SSL_ST_MASK                     = 0x0FFF;
%constant int SSL_ST_INIT                     = (SSL_ST_CONNECT|SSL_ST_ACCEPT);
%constant int SSL_ST_BEFORE                   = 0x4000;
%constant int SSL_ST_OK                       = 0x03;
%constant int SSL_ST_RENEGOTIATE              = (0x04|SSL_ST_INIT);

%constant int SSL_CB_LOOP                     = 0x01;
%constant int SSL_CB_EXIT                     = 0x02;
%constant int SSL_CB_READ                     = 0x04;
%constant int SSL_CB_WRITE                    = 0x08;
%constant int SSL_CB_ALERT                    = 0x4000; /* used in callback */
%constant int SSL_CB_READ_ALERT               = (SSL_CB_ALERT|SSL_CB_READ);
%constant int SSL_CB_WRITE_ALERT              = (SSL_CB_ALERT|SSL_CB_WRITE);
%constant int SSL_CB_ACCEPT_LOOP              = (SSL_ST_ACCEPT|SSL_CB_LOOP);
%constant int SSL_CB_ACCEPT_EXIT              = (SSL_ST_ACCEPT|SSL_CB_EXIT);
%constant int SSL_CB_CONNECT_LOOP             = (SSL_ST_CONNECT|SSL_CB_LOOP);
%constant int SSL_CB_CONNECT_EXIT             = (SSL_ST_CONNECT|SSL_CB_EXIT);
%constant int SSL_CB_HANDSHAKE_START          = 0x10;
%constant int SSL_CB_HANDSHAKE_DONE           = 0x20;

%constant int SSL_SENT_SHUTDOWN	          = 1;
%constant int SSL_RECEIVED_SHUTDOWN	  = 2;

%constant int SSL_OP_ALL                  = 0x00000FFFL;

%constant int SSL_OP_NO_SSLv2             = 0x01000000L;
%constant int SSL_OP_NO_SSLv3             = 0x02000000L;
%constant int SSL_OP_NO_TLSv1             = 0x04000000L;
%constant int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800L;

%constant int SSL_MODE_ENABLE_PARTIAL_WRITE = SSL_MODE_ENABLE_PARTIAL_WRITE;
%constant int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = SSL_MODE_ENABLE_PARTIAL_WRITE;
%constant int SSL_MODE_AUTO_RETRY           = SSL_MODE_AUTO_RETRY;

%inline %{
static PyObject *_ssl_err;

void ssl_init(PyObject *ssl_err) {
    SSL_library_init();
    SSL_load_error_strings();
    Py_INCREF(ssl_err);
    _ssl_err = ssl_err;
}

void ssl_ctx_passphrase_callback(SSL_CTX *ctx, PyObject *pyfunc) {
    SSL_CTX_set_default_passwd_cb(ctx, passphrase_callback);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)pyfunc);
    Py_INCREF(pyfunc);
}

int ssl_ctx_use_cert(SSL_CTX *ctx, char *file) {
    int i;
    
    if (!(i = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM))) {
        PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    return i;
}

int ssl_ctx_use_cert_chain(SSL_CTX *ctx, char *file) {
    int i;

    if (!(i = SSL_CTX_use_certificate_chain_file(ctx, file))) {
        PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    return i;
}


int ssl_ctx_use_privkey(SSL_CTX *ctx, char *file) {
    int i;
    
    if (!(i = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM))) {
        PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    return i;
}

int ssl_ctx_check_privkey(SSL_CTX *ctx) {
    int ret;
    
    if (!(ret = SSL_CTX_check_private_key(ctx))) {
        PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    return ret;
}

void ssl_ctx_set_client_CA_list_from_file(SSL_CTX *ctx, const char *ca_file) {
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_file));
}

void ssl_ctx_set_verify_default(SSL_CTX *ctx, int mode) {
    SSL_CTX_set_verify(ctx, mode, NULL);
}

void ssl_ctx_set_verify(SSL_CTX *ctx, int mode, PyObject *pyfunc) {
    Py_XDECREF(ssl_verify_cb_func);
    Py_INCREF(pyfunc);
    ssl_verify_cb_func = pyfunc;
    SSL_CTX_set_verify(ctx, mode, ssl_verify_callback);
}

int ssl_ctx_set_session_id_context(SSL_CTX *ctx, PyObject *sid_ctx) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(sid_ctx, &buf, &len) == -1)
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(sid_ctx)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    len = PyString_Size(sid_ctx);
    buf = (const void *)PyString_AsString(sid_ctx);
#endif
    return SSL_CTX_set_session_id_context(ctx, buf, len);
}

void ssl_ctx_set_info_callback(SSL_CTX *ctx, PyObject *pyfunc) {
    Py_XDECREF(ssl_info_cb_func);
    Py_INCREF(pyfunc);
    ssl_info_cb_func = pyfunc;
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);
}

long ssl_ctx_set_tmp_dh(SSL_CTX *ctx, DH* dh) {
    SSL_CTX_set_tmp_dh(ctx, dh);
}

void ssl_ctx_set_tmp_dh_callback(SSL_CTX *ctx,  PyObject *pyfunc) {
    Py_XDECREF(ssl_set_tmp_dh_cb_func);
    Py_INCREF(pyfunc);
    ssl_set_tmp_dh_cb_func = pyfunc;
    SSL_CTX_set_tmp_dh_callback(ctx, ssl_set_tmp_dh_callback);
}

long ssl_ctx_set_tmp_rsa(SSL_CTX *ctx, RSA* rsa) {
    SSL_CTX_set_tmp_dh(ctx, rsa);
}

void ssl_ctx_set_tmp_rsa_callback(SSL_CTX *ctx,  PyObject *pyfunc) {
    Py_XDECREF(ssl_set_tmp_rsa_cb_func);
    Py_INCREF(pyfunc);
    ssl_set_tmp_rsa_cb_func = pyfunc;
    SSL_CTX_set_tmp_rsa_callback(ctx, ssl_set_tmp_rsa_callback);
}

int ssl_ctx_load_verify_locations(SSL_CTX *ctx, const char *cafile, const char *capath) {
    return SSL_CTX_load_verify_locations(ctx, cafile, capath);
}

/* SSL_CTX_set_options is a macro. */
long ssl_ctx_set_options(SSL_CTX *ctx, long op) {
    return SSL_CTX_set_options(ctx, op);
}

int bio_set_ssl(BIO *bio, SSL *ssl, int flag) {
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    return BIO_ctrl(bio, BIO_C_SET_SSL, flag, (char *)ssl);
}

long ssl_set_mode(SSL *ssl, long mode) {
    return SSL_set_mode(ssl, mode);
}

long ssl_get_mode(SSL *ssl) {
    return SSL_get_mode(ssl);
}

void ssl_set_client_CA_list_from_file(SSL *ssl, const char *ca_file) {
    SSL_set_client_CA_list(ssl, SSL_load_client_CA_file(ca_file));
}

void ssl_set_client_CA_list_from_context(SSL *ssl, SSL_CTX *ctx) {
    SSL_set_client_CA_list(ssl, SSL_CTX_get_client_CA_list(ctx));
}

int ssl_set_session_id_context(SSL *ssl, PyObject *sid_ctx) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(sid_ctx, &buf, &len) == -1)
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(sid_ctx)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    len = PyString_Size(sid_ctx);
    buf = (const void *)PyString_AsString(sid_ctx);
#endif
    return SSL_set_session_id_context(ssl, buf, len);
}

int ssl_set_fd(SSL *ssl, int fd) {
    int ret;
    
    if (!(ret = SSL_set_fd(ssl, fd))) {
        PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    return ret;
}

PyObject *ssl_accept(SSL *ssl) {
    PyObject *obj;
    int r, err;
    PyThreadState *_save;

    if (thread_mode) {
        _save = (PyThreadState *)PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
    r = SSL_accept(ssl);
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            obj = PyInt_FromLong((long)1);
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            obj = PyInt_FromLong((long)0);
            break;
        case SSL_ERROR_SSL:
            PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            obj = NULL;
            break;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(err));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
            obj = NULL;
            break;
    }
    return obj;
}

PyObject *ssl_connect(SSL *ssl) {
    PyObject *obj;
    int r, err;
    PyThreadState *_save;

    if (thread_mode) {
        _save = (PyThreadState *)PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
    r = SSL_connect(ssl);
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            obj = PyInt_FromLong((long)1);
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            obj = PyInt_FromLong((long)0);
            break;
        case SSL_ERROR_SSL:
            PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            obj = NULL;
            break;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(err));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
            obj = NULL;
            break;
    }
    return obj;
}

void ssl_set_shutdown1(SSL *ssl, int mode) {
    SSL_set_shutdown(ssl, mode);
}

PyObject *ssl_read(SSL *ssl, int num) {
    PyObject *obj;
    void *buf;
    int r, err;
    PyThreadState *_save;

    if (!(buf = PyMem_Malloc(num))) {
        PyErr_SetString(PyExc_MemoryError, "ssl_read");
        return NULL;
    }
    if (thread_mode) {
        _save = (PyThreadState *)PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
    r = SSL_read(ssl, buf, num);
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            buf = PyMem_Realloc(buf, r);
            obj = PyString_FromStringAndSize(buf, r);
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            Py_INCREF(Py_None);
            obj = Py_None;
            break;
        case SSL_ERROR_SSL:
            PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            obj = NULL;
            break;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(err));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
            obj = NULL;
            break;
    }
    PyMem_Free(buf);
    return obj;
}

PyObject *ssl_read_nbio(SSL *ssl, int num) {
    PyObject *obj;
    void *buf;
    int r, err;

    if (!(buf = PyMem_Malloc(num))) {
        PyErr_SetString(PyExc_MemoryError, "ssl_read");
        return NULL;
    }
    r = SSL_read(ssl, buf, num);
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            buf = PyMem_Realloc(buf, r);
            obj = PyString_FromStringAndSize(buf, r);
            break;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            Py_INCREF(Py_None);
            obj = Py_None;
            break;
        case SSL_ERROR_SSL:
            PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            obj = NULL;
            break;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(err));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
            obj = NULL;
            break;
    }
    PyMem_Free(buf);
    return obj;
}

int ssl_write(SSL *ssl, PyObject *blob) {
    const void *buf;
    int len, r, err;
    PyThreadState *_save;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    len = PyString_Size(blob);
    buf = (const void *)PyString_AsString(blob);
#endif
    if (thread_mode) {
        _save = (PyThreadState *)PyEval_SaveThread();
        SSL_set_app_data(ssl, _save);
    }
    r = SSL_write(ssl, buf, len);
    if (thread_mode) {
        _save = (PyThreadState *)SSL_get_app_data(ssl);
        PyEval_RestoreThread(_save);
    }
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            return r;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            return -1;
        case SSL_ERROR_SSL:
            PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            return -1;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(ERR_get_error()));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
        default:
            return -1;
    }
}

int ssl_write_nbio(SSL *ssl, PyObject *blob) {
    const void *buf;
    int len, r, err;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    len = PyString_Size(blob);
    buf = (const void *)PyString_AsString(blob);
#endif
    r = SSL_write(ssl, buf, len);
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            return r;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            return -1;
        case SSL_ERROR_SSL:
            return -1;
        case SSL_ERROR_SYSCALL:
            err = ERR_get_error();
            if (err)
                PyErr_SetString(_ssl_err, ERR_reason_error_string(err));
            else if (r == 0)
                PyErr_SetString(_ssl_err, "unexpected eof");
            else if (r == -1)
                PyErr_SetFromErrno(_ssl_err);
        default:
            return -1;
    }
}

int ssl_cipher_get_bits(SSL_CIPHER *c) {
    return SSL_CIPHER_get_bits(c, NULL);
}

STACK *ssl_get_ciphers(SSL *ssl) {
    return (STACK *)SSL_get_ciphers(ssl);
}

int sk_ssl_cipher_num(STACK *stack) {
    return sk_num(stack);
}

SSL_CIPHER *sk_ssl_cipher_value(STACK *stack, int idx) {
    return (SSL_CIPHER *)sk_value(stack, idx);
}

STACK *ssl_get_peer_cert_chain(SSL *ssl) {
    return (STACK *)SSL_get_peer_cert_chain(ssl);
}

int sk_x509_num(STACK *stack) {
    return sk_num(stack);
}

X509 *sk_x509_value(STACK *stack, int idx) {
    return (X509 *)sk_value(stack, idx);
}

void i2d_ssl_session(BIO *bio, SSL_SESSION *sess) {
    i2d_SSL_SESSION_bio(bio, sess);
}

SSL_SESSION *ssl_session_read_pem(BIO *bio) {
    return PEM_read_bio_SSL_SESSION(bio, NULL, NULL, NULL);
}

int ssl_session_write_pem(SSL_SESSION *sess, BIO *bio) {
    return PEM_write_bio_SSL_SESSION(bio, sess);
}

int ssl_ctx_set_session_cache_mode(SSL_CTX *ctx, int mode)
{
    return SSL_CTX_set_session_cache_mode(ctx, mode);
}

int ssl_ctx_get_session_cache_mode(SSL_CTX *ctx)
{
    return SSL_CTX_get_session_cache_mode(ctx);
}

static long ssl_ctx_set_cache_size(SSL_CTX *ctx, long arg)
{
  return SSL_CTX_sess_set_cache_size(ctx, arg);
}

int ssl_is_init_finished(SSL *ssl)
{
  return SSL_is_init_finished(ssl);
}
%}

