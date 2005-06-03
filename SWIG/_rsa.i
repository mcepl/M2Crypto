/* Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
%}

%apply Pointer NONNULL { RSA * };
%apply Pointer NONNULL { PyObject *pyfunc };

%name(rsa_new) extern RSA *RSA_new(void);
%name(rsa_free) extern void RSA_free(RSA *);
%name(rsa_size) extern int RSA_size(const RSA *);
%name(rsa_check_key) extern int RSA_check_key(const RSA *);

%constant int no_padding        = RSA_NO_PADDING;
%constant int pkcs1_padding     = RSA_PKCS1_PADDING;
%constant int sslv23_padding    = RSA_SSLV23_PADDING;
%constant int pkcs1_oaep_padding = RSA_PKCS1_OAEP_PADDING;

%inline %{
static PyObject *_rsa_err;

void rsa_init(PyObject *rsa_err) {
    Py_INCREF(rsa_err);
    _rsa_err = rsa_err;
}

RSA *rsa_read_key(BIO *f, PyObject *pyfunc) {
    RSA *rsa;

    Py_INCREF(pyfunc);
    rsa = PEM_read_bio_RSAPrivateKey(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return rsa;
}

int rsa_write_key(RSA *rsa, BIO *f, EVP_CIPHER *cipher, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    ret = PEM_write_bio_RSAPrivateKey(f, rsa, cipher, NULL, 0,
        passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

int rsa_write_key_no_cipher(RSA *rsa, BIO *f, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    ret = PEM_write_bio_RSAPrivateKey(f, rsa, NULL, NULL, 0, 
				      passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

RSA *rsa_read_pub_key(BIO *f) {
    /* return PEM_read_bio_RSAPublicKey(f, NULL, NULL, NULL);   
    Broken by incompatible change introduced in OpenSSL 0.9.6. */
    return PEM_read_bio_RSA_PUBKEY(f, NULL, NULL, NULL);   
}

int rsa_write_pub_key(RSA *rsa, BIO *f) {
    /* return PEM_write_bio_RSAPublicKey(f, rsa);
    Broken by incompatible change introduced in OpenSSL 0.9.6. */
    return PEM_write_bio_RSA_PUBKEY(f, rsa);
}

PyObject *rsa_get_e(RSA *rsa) {
    if (!rsa->e) {
        PyErr_SetString(_rsa_err, "'e' is unset");
        return NULL;
    }
    return bn_to_mpi(rsa->e);
}

PyObject *rsa_get_n(RSA *rsa) {
    if (!rsa->n) {
        PyErr_SetString(_rsa_err, "'n' is unset");
        return NULL;
    }
    return bn_to_mpi(rsa->n);
}

PyObject *rsa_set_e(RSA *rsa, PyObject *value) {
    BIGNUM *bn;
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
    if (!(bn = BN_mpi2bn((unsigned char *)vbuf, vlen, NULL))) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (rsa->e)
        BN_free(rsa->e);
    rsa->e = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rsa_set_n(RSA *rsa, PyObject *value) {
    BIGNUM *bn;
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
    if (!(bn = BN_mpi2bn((unsigned char *)vbuf, vlen, NULL))) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (rsa->n)
        BN_free(rsa->n);
    rsa->n = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rsa_set_e_bin(RSA *rsa, PyObject *value) {
    BIGNUM *bn;
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
    if (!(bn = BN_bin2bn((unsigned char *)vbuf, vlen, NULL))) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (rsa->e)
        BN_free(rsa->e);
    rsa->e = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rsa_set_n_bin(RSA *rsa, PyObject *value) {
    BIGNUM *bn;
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
    if (!(bn = BN_bin2bn((unsigned char *)vbuf, vlen, NULL))) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (rsa->n)
        BN_free(rsa->n);
    rsa->n = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rsa_private_encrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(from, &fbuf, &flen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(from)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    flen = PyString_Size(from);
    fbuf = (const void *)PyString_AsString(from);
#endif
    if (!(tbuf = PyMem_Malloc(BN_num_bytes(rsa->n)))) {
        PyErr_SetString(PyExc_MemoryError, "rsa_private_encrypt");
        return NULL;
    }
    tlen = RSA_private_encrypt(flen, (unsigned char *)fbuf, 
        (unsigned char *)tbuf, rsa, padding);
    if (tlen == -1) {
        PyMem_Free(tbuf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_public_decrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(from, &fbuf, &flen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(from)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    flen = PyString_Size(from);
    fbuf = (const void *)PyString_AsString(from);
#endif
    if (!(tbuf = PyMem_Malloc(BN_num_bytes(rsa->n)))) {
        PyErr_SetString(PyExc_MemoryError, "rsa_public_decrypt");
        return NULL;
    }
    tlen = RSA_public_decrypt(flen, (unsigned char *)fbuf, 
        (unsigned char *)tbuf, rsa, padding);
    if (tlen == -1) {
        PyMem_Free(tbuf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_public_encrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(from, &fbuf, &flen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(from)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    flen = PyString_Size(from);
    fbuf = (const void *)PyString_AsString(from);
#endif
    if (!(tbuf = PyMem_Malloc(BN_num_bytes(rsa->n)))) {
        PyErr_SetString(PyExc_MemoryError, "rsa_public_encrypt");
        return NULL;
    }
    tlen = RSA_public_encrypt(flen, (unsigned char *)fbuf, 
        (unsigned char *)tbuf, rsa, padding);
    if (tlen == -1) {
        PyMem_Free(tbuf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_private_decrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(from, &fbuf, &flen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(from)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    flen = PyString_Size(from);
    fbuf = (const void *)PyString_AsString(from);
#endif
    if (!(tbuf = PyMem_Malloc(BN_num_bytes(rsa->n)))) {
        PyErr_SetString(PyExc_MemoryError, "rsa_private_decrypt");
        return NULL;
    }
    tlen = RSA_private_decrypt(flen, (unsigned char *)fbuf, 
        (unsigned char *)tbuf, rsa, padding);
    if (tlen == -1) {
        PyMem_Free(tbuf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
    PyMem_Free(tbuf);
    return ret;
}

void genrsa_callback(int p, int n, void *arg) {
    PyObject *argv, *ret, *cbfunc;

    cbfunc = (PyObject *)arg; 
    argv = Py_BuildValue("(ii)", p, n);
    ret = PyEval_CallObject(cbfunc, argv);
    PyErr_Clear();
    Py_DECREF(argv);
    Py_XDECREF(ret);
}

RSA *rsa_generate_key(int bits, unsigned long e, PyObject *pyfunc) {
    RSA *rsa;

    Py_INCREF(pyfunc);
    rsa = RSA_generate_key(bits, e, genrsa_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    if (!rsa) 
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
    return rsa;
}

int rsa_type_check(RSA *rsa) {
    return 1;
}

int rsa_check_pub_key(RSA *rsa) {
    return (rsa->e) && (rsa->n);
}

int rsa_write_key_der(RSA *rsa, BIO *bio) {
    return i2d_RSAPrivateKey_bio(bio, rsa);
}
%}

