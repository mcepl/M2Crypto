/* Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
%}

%apply Pointer NONNULL { RSA * };
%apply Pointer NONNULL { PyObject *pyfunc };

%rename(rsa_size) RSA_size;
extern int RSA_size(const RSA*);
%rename(rsa_new) RSA_new;
extern RSA *RSA_new(void);
%rename(rsa_free) RSA_free;
extern void RSA_free(RSA *);
%rename(rsa_check_key) RSA_check_key;
extern int RSA_check_key(const RSA *);

%constant int no_padding        = RSA_NO_PADDING;
%constant int pkcs1_padding     = RSA_PKCS1_PADDING;
%constant int sslv23_padding    = RSA_SSLV23_PADDING;
%constant int pkcs1_oaep_padding = RSA_PKCS1_OAEP_PADDING;

%constant int NID_sha1 = NID_sha1;

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
%constant int NID_sha224 = NID_sha224;
%constant int NID_sha256 = NID_sha256;
%constant int NID_sha384 = NID_sha384;
%constant int NID_sha512 = NID_sha512;
#endif

%constant int NID_md5 = NID_md5;

%constant int NID_ripemd160 = NID_ripemd160;

%warnfilter(454) _rsa_err;
%inline %{
static PyObject *_rsa_err;

void rsa_init(PyObject *rsa_err) {
    Py_INCREF(rsa_err);
    _rsa_err = rsa_err;
}
%}

%inline %{
RSA *rsa_read_key(BIO *f, PyObject *pyfunc) {
    RSA *rsa;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    rsa = PEM_read_bio_RSAPrivateKey(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);
    return rsa;
}
%}

%inline %{
int rsa_write_key(RSA *rsa, BIO *f, EVP_CIPHER *cipher, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_write_bio_RSAPrivateKey(f, rsa, cipher, NULL, 0,
        passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);
    return ret;
}
%}

%inline %{
int rsa_write_key_no_cipher(RSA *rsa, BIO *f, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    Py_BEGIN_ALLOW_THREADS
    ret = PEM_write_bio_RSAPrivateKey(f, rsa, NULL, NULL, 0,
                      passphrase_callback, (void *)pyfunc);
    Py_END_ALLOW_THREADS
    Py_DECREF(pyfunc);
    return ret;
}
%}

%threadallow rsa_read_pub_key;
%inline %{
RSA *rsa_read_pub_key(BIO *f) {
    return PEM_read_bio_RSA_PUBKEY(f, NULL, NULL, NULL);
}
%}

%threadallow rsa_write_pub_key;
%inline %{
int rsa_write_pub_key(RSA *rsa, BIO *f) {
    return PEM_write_bio_RSA_PUBKEY(f, rsa);
}

PyObject *rsa_get_e(RSA *rsa) {
    BIGNUM* e = NULL;
    RSA_get0_key(rsa, NULL, &e, NULL);
    if (!e) {
        PyErr_SetString(_rsa_err, "'e' is unset");
        return NULL;
    }
    return bn_to_mpi(e);
}

PyObject *rsa_get_n(RSA *rsa) {
    BIGNUM* n = NULL;
    RSA_get0_key(rsa, &n, NULL, NULL);
    if (!n) {
        PyErr_SetString(_rsa_err, "'n' is unset");
        return NULL;
    }
    return bn_to_mpi(n);
}

PyObject *rsa_set_en(RSA *rsa, PyObject *eval, PyObject* nval) {
    BIGNUM* e, *n;

    if (!(e = m2_PyObject_AsBIGNUM(eval, _rsa_err)) || 
        !(n = m2_PyObject_AsBIGNUM(nval, _rsa_err))) {
        return NULL;
    }

    if (!RSA_set0_key(rsa, n, e, NULL)) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        BN_free(e);
        BN_free(n);
        return NULL;
    }
    Py_RETURN_NONE;
}

static BIGNUM* PyObject_Bin_AsBIGNUM(PyObject* value) {
    BIGNUM* bn;
    const void* vbuf;
    int vlen;

    if (m2_PyObject_AsReadBufferInt(value, &vbuf, &vlen) == -1)
        return NULL;

    if (!(bn = BN_bin2bn((unsigned char *)vbuf, vlen, NULL))) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
        }

    return bn;
}

PyObject *rsa_set_en_bin(RSA *rsa, PyObject *eval, PyObject* nval) {
    BIGNUM* e, *n;

    if (!(e = PyObject_Bin_AsBIGNUM(eval)) || 
        !(n = PyObject_Bin_AsBIGNUM(nval))) {
        return NULL;
    }

    if (!RSA_set0_key(rsa, e, n, NULL)) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        BN_free(e);
        BN_free(n);
        return NULL;
    }
    Py_RETURN_NONE;
}

PyObject *rsa_private_encrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

    if (m2_PyObject_AsReadBufferInt(from, &fbuf, &flen) == -1)
        return NULL;

    if (!(tbuf = PyMem_Malloc(RSA_size(rsa)))) {
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

#if PY_MAJOR_VERSION >= 3
    ret = PyBytes_FromStringAndSize((const char *)tbuf, tlen);
#else
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
#endif // PY_MAJOR_VERSION >= 3

    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_public_decrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

    if (m2_PyObject_AsReadBufferInt(from, &fbuf, &flen) == -1)
        return NULL;

    /* OpenSSL docs are confused here: it says we only need buffer
     * 'RSA_size()-11', but it is true only for RSA PKCS#1 type 1
     * padding. For other uses we need to use different sizes. */
    if (!(tbuf = PyMem_Malloc(RSA_size(rsa)))) {
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

#if PY_MAJOR_VERSION >= 3
    ret = PyBytes_FromStringAndSize((const char *)tbuf, tlen);
#else
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
#endif // PY_MAJOR_VERSION >= 3

    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_public_encrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

    if (m2_PyObject_AsReadBufferInt(from, &fbuf, &flen) == -1)
        return NULL;

    if (!(tbuf = PyMem_Malloc(RSA_size(rsa)))) {
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

#if PY_MAJOR_VERSION >= 3
    ret = PyBytes_FromStringAndSize((const char *)tbuf, tlen);
#else
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
#endif // PY_MAJOR_VERSION >= 3

    PyMem_Free(tbuf);
    return ret;
}

PyObject *rsa_private_decrypt(RSA *rsa, PyObject *from, int padding) {
    const void *fbuf;
    void *tbuf;
    int flen, tlen;
    PyObject *ret;

    if (m2_PyObject_AsReadBufferInt(from, &fbuf, &flen) == -1)
        return NULL;

    if (!(tbuf = PyMem_Malloc(RSA_size(rsa)))) {
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
#if PY_MAJOR_VERSION >= 3
    ret = PyBytes_FromStringAndSize((const char *)tbuf, tlen);
#else
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
#endif // PY_MAJOR_VERSION >= 3

    PyMem_Free(tbuf);
    return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x0090708fL
PyObject *rsa_padding_add_pkcs1_pss(RSA *rsa, PyObject *digest, EVP_MD *hash, int salt_length) {
    const void *dbuf;
    unsigned char *tbuf;
    int dlen, result, tlen;
    PyObject *ret;

    if (m2_PyObject_AsReadBufferInt(digest, &dbuf, &dlen) == -1)
        return NULL;

    tlen = RSA_size(rsa);

    if (!(tbuf = OPENSSL_malloc(tlen))) {
        PyErr_SetString(PyExc_MemoryError, "rsa_padding_add_pkcs1_pss");
        return NULL;
    }
    result = RSA_padding_add_PKCS1_PSS(
        rsa,
        tbuf,
        (unsigned char *)dbuf,
        hash,
        salt_length);

    if (result == -1) {
        OPENSSL_cleanse(tbuf, tlen);
        OPENSSL_free(tbuf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
#if PY_MAJOR_VERSION >= 3
    ret = PyBytes_FromStringAndSize((const char *)tbuf, tlen);
#else
    ret = PyString_FromStringAndSize((const char *)tbuf, tlen);
#endif // PY_MAJOR_VERSION >= 3
    OPENSSL_cleanse(tbuf, tlen);
    OPENSSL_free(tbuf);
    return ret;
}

int rsa_verify_pkcs1_pss(RSA *rsa, PyObject *digest, PyObject *signature, EVP_MD *hash, int salt_length) {
    const void *dbuf;
    const void *sbuf;
    int dlen, slen, ret;

    if (m2_PyObject_AsReadBufferInt(digest, &dbuf, &dlen) == -1) {
        return 0;
    }

    if (m2_PyObject_AsReadBufferInt(signature, &sbuf, &slen) == -1) {
        return 0;
    }

    ret = RSA_verify_PKCS1_PSS(
        rsa,
        (unsigned char *)dbuf,
        hash,
        (unsigned char *)sbuf,
        salt_length);

    return ret;
}
#endif

PyObject *rsa_sign(RSA *rsa, PyObject *py_digest_string, int method_type) {
    int digest_len = 0;
    int buf_len = 0;
    int ret = 0;
    unsigned int real_buf_len = 0;
    char *digest_string = NULL;
    unsigned char * sign_buf = NULL;
    PyObject *signature;

    ret = m2_PyString_AsStringAndSizeInt(py_digest_string, &digest_string,
                                         &digest_len);
    if (ret == -1) {
        /* PyString_AsStringAndSize raises the correct exceptions. */
        return NULL;
    }

    buf_len = RSA_size(rsa);
    sign_buf = (unsigned char *)PyMem_Malloc(buf_len);
    ret = RSA_sign(method_type, (const unsigned char *)digest_string, digest_len,
                   sign_buf, &real_buf_len, rsa);

    if (!ret) {
        PyMem_Free(sign_buf);
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    signature =  PyBytes_FromStringAndSize((const char*) sign_buf, buf_len);
#else
    signature =  PyString_FromStringAndSize((const char*) sign_buf, buf_len);
#endif

    PyMem_Free(sign_buf);
    return signature;
}

int rsa_verify(RSA *rsa, PyObject *py_verify_string, PyObject* py_sign_string, int method_type){
    int ret = 0;
    char * sign_string = NULL;
    char * verify_string = NULL;
    int verify_len = 0;
    int sign_len = 0;

    ret = m2_PyString_AsStringAndSizeInt(py_verify_string, &verify_string,
                                         &verify_len);
    if (ret == -1) {
        /* PyString_AsStringAndSize raises the correct exceptions. */
        return 0;
    }
    ret = m2_PyString_AsStringAndSizeInt(py_sign_string, &sign_string,
                                         &sign_len);
    if (ret == -1) {
        return 0;
    }

    ret = RSA_verify(method_type, (unsigned char *) verify_string,
                     verify_len, (unsigned char *) sign_string,
                     sign_len, rsa);
    if (!ret) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
    }
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

PyObject *rsa_generate_key(int bits, unsigned long e, PyObject *pyfunc) {
    RSA *rsa;
    PyObject *self = NULL; /* bug in SWIG_NewPointerObj as of 3.0.5 */

    Py_INCREF(pyfunc);
    rsa = RSA_generate_key(bits, e, genrsa_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    if (!rsa) {
        PyErr_SetString(_rsa_err, ERR_reason_error_string(ERR_get_error()));
	return NULL;
    }
    return SWIG_NewPointerObj((void *)rsa, SWIGTYPE_p_RSA, 0);
}

int rsa_type_check(RSA *rsa) {
    return 1;
}

int rsa_check_pub_key(RSA *rsa) {
    BIGNUM* n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);
    return n && e;
}
%}

%threadallow rsa_write_key_der;
%inline %{
int rsa_write_key_der(RSA *rsa, BIO *bio) {
    return i2d_RSAPrivateKey_bio(bio, rsa);
}
%}
