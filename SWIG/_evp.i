/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* 
Copyright (c) 1999 Ng Pheng Siong. All rights reserved.

Portions Copyright (c) 2004 Open Source Applications Foundation.
Author: Heikki Toivonen
*/
/* $Id$ */

%{
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
%}

%apply Pointer NONNULL { EVP_MD_CTX * };
%apply Pointer NONNULL { EVP_MD * };
%apply Pointer NONNULL { EVP_PKEY * };
%apply Pointer NONNULL { HMAC_CTX * };
%apply Pointer NONNULL { EVP_CIPHER_CTX * };
%apply Pointer NONNULL { EVP_CIPHER * };
%apply Pointer NONNULL { RSA * };

%name(md5) extern const EVP_MD *EVP_md5(void);
%name(sha1) extern const EVP_MD *EVP_sha1(void);
%name(ripemd160) extern const EVP_MD *EVP_ripemd160(void);
%name(digest_init) extern int EVP_DigestInit(EVP_MD_CTX *, const EVP_MD *);

%name(des_ecb) extern const EVP_CIPHER *EVP_des_ecb(void);
%name(des_ede_ecb) extern const EVP_CIPHER *EVP_des_ede(void);
%name(des_ede3_ecb) extern const EVP_CIPHER *EVP_des_ede3(void);
%name(des_cbc) extern const EVP_CIPHER *EVP_des_cbc(void);
%name(des_ede_cbc) extern const EVP_CIPHER *EVP_des_ede_cbc(void);
%name(des_ede3_cbc) extern const EVP_CIPHER *EVP_des_ede3_cbc(void);
%name(des_cfb) extern const EVP_CIPHER *EVP_des_cfb(void);
%name(des_ede_cfb) extern const EVP_CIPHER *EVP_des_ede_cfb(void);
%name(des_ede3_cfb) extern const EVP_CIPHER *EVP_des_ede3_cfb(void);
%name(des_ofb) extern const EVP_CIPHER *EVP_des_ofb(void);
%name(des_ede_ofb) extern const EVP_CIPHER *EVP_des_ede_ofb(void);
%name(des_ede3_ofb) extern const EVP_CIPHER *EVP_des_ede3_ofb(void);
%name(bf_ecb) extern const EVP_CIPHER *EVP_bf_ecb(void);
%name(bf_cbc) extern const EVP_CIPHER *EVP_bf_cbc(void);
%name(bf_cfb) extern const EVP_CIPHER *EVP_bf_cfb(void);
%name(bf_ofb) extern const EVP_CIPHER *EVP_bf_ofb(void);
/*
%name(idea_ecb) extern const EVP_CIPHER *EVP_idea_ecb(void);
%name(idea_cbc) extern const EVP_CIPHER *EVP_idea_cbc(void);
%name(idea_cfb) extern const EVP_CIPHER *EVP_idea_cfb(void);
%name(idea_ofb) extern const EVP_CIPHER *EVP_idea_ofb(void);
*/
%name(cast5_ecb) extern const EVP_CIPHER *EVP_cast5_ecb(void);
%name(cast5_cbc) extern const EVP_CIPHER *EVP_cast5_cbc(void);
%name(cast5_cfb) extern const EVP_CIPHER *EVP_cast5_cfb(void);
%name(cast5_ofb) extern const EVP_CIPHER *EVP_cast5_ofb(void);
/*
%name(rc5_ecb) extern const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
%name(rc5_cbc) extern const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
%name(rc5_cfb) extern const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void);
%name(rc5_ofb) extern const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
*/
%name(rc4) extern const EVP_CIPHER *EVP_rc4(void);
%name(rc2_40_cbc) extern const EVP_CIPHER *EVP_rc2_40_cbc(void);
%name(aes_128_ecb) extern const EVP_CIPHER *EVP_aes_128_ecb(void);
%name(aes_128_cbc) extern const EVP_CIPHER *EVP_aes_128_cbc(void);
%name(aes_128_cfb) extern const EVP_CIPHER *EVP_aes_128_cfb(void);
%name(aes_128_ofb) extern const EVP_CIPHER *EVP_aes_128_ofb(void);
%name(aes_192_ecb) extern const EVP_CIPHER *EVP_aes_192_ecb(void);
%name(aes_192_cbc) extern const EVP_CIPHER *EVP_aes_192_cbc(void);
%name(aes_192_cfb) extern const EVP_CIPHER *EVP_aes_192_cfb(void);
%name(aes_192_ofb) extern const EVP_CIPHER *EVP_aes_192_ofb(void);
%name(aes_256_ecb) extern const EVP_CIPHER *EVP_aes_256_ecb(void);
%name(aes_256_cbc) extern const EVP_CIPHER *EVP_aes_256_cbc(void);
%name(aes_256_cfb) extern const EVP_CIPHER *EVP_aes_256_cfb(void);
%name(aes_256_ofb) extern const EVP_CIPHER *EVP_aes_256_ofb(void);

%name(pkey_new) extern EVP_PKEY *EVP_PKEY_new(void);
%name(pkey_free) extern void EVP_PKEY_free(EVP_PKEY *);
%name(pkey_assign) extern int EVP_PKEY_assign(EVP_PKEY *, int, char *);
%name(pkey_set1_rsa) extern int EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);
%name(pkey_get1_rsa) extern RSA* EVP_PKEY_get1_RSA(EVP_PKEY *);
%name(sign_init) extern int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
%name(verify_init) extern int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);

%inline %{
#define PKCS5_SALT_LEN  8

static PyObject *_evp_err;

void evp_init(PyObject *evp_err) {
    Py_INCREF(evp_err);
    _evp_err = evp_err;
}

EVP_MD_CTX *md_ctx_new(void) {
    EVP_MD_CTX *ctx;

    if (!(ctx = (EVP_MD_CTX *)PyMem_Malloc(sizeof(EVP_MD_CTX)))) {
        PyErr_SetString(PyExc_MemoryError, "md_ctx_new");
    }
    return ctx;
}

void md_ctx_free(EVP_MD_CTX *ctx) {
    PyMem_Free((void *)ctx);
}

PyObject *digest_update(EVP_MD_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    EVP_DigestUpdate(ctx, buf, (unsigned int)len);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *digest_final(EVP_MD_CTX *ctx) {
    void *blob;
    int blen;
    PyObject *ret;

    if (!(blob = PyMem_Malloc(ctx->digest->md_size))) {
        PyErr_SetString(PyExc_MemoryError, "digest_final");
        return NULL;
    }
    EVP_DigestFinal(ctx, blob, (unsigned int *)&blen);
    ret = PyString_FromStringAndSize(blob, blen);
    PyMem_Free(blob);
    return ret;
}

HMAC_CTX *hmac_ctx_new(void) {
    HMAC_CTX *ctx;

    if (!(ctx = (HMAC_CTX *)PyMem_Malloc(sizeof(HMAC_CTX)))) {
        PyErr_SetString(PyExc_MemoryError, "hmac_ctx_new");
    }
    return ctx;
}

void hmac_ctx_free(HMAC_CTX *ctx) {
    HMAC_cleanup(ctx);
    PyMem_Free((void *)ctx);
}

PyObject *hmac_init(HMAC_CTX *ctx, PyObject *key, const EVP_MD *md) {
    const void *kbuf;
    int klen;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(key)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    klen = PyString_Size(key);
    kbuf = PyString_AsString(key);
#endif
    HMAC_Init(ctx, kbuf, klen, md);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *hmac_update(HMAC_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    HMAC_Update(ctx, buf, (unsigned int)len);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *hmac_final(HMAC_CTX *ctx) {
    void *blob;
    int blen;
    PyObject *ret;

    if (!(blob = PyMem_Malloc(ctx->md->md_size))) {
        PyErr_SetString(PyExc_MemoryError, "hmac_final");
        return NULL;
    }
    HMAC_Final(ctx, blob, (unsigned int *)&blen);
    ret = PyString_FromStringAndSize(blob, blen);
    PyMem_Free(blob);
    return ret;
}

PyObject *hmac(PyObject *key, PyObject *data, const EVP_MD *md) {
    const void *kbuf, *dbuf;
    void *blob;
    int klen, dlen, blen;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if ((PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        || (PyObject_AsReadBuffer(data, &dbuf, &dlen) == -1))
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(key)
        || !PyString_Check(data)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    klen = PyString_Size(key);
    kbuf = (const void *)PyString_AsString(key);
    dlen = PyString_Size(data);
    dbuf = (const void *)PyString_AsString(data);
#endif
    if (!(blob = PyMem_Malloc(EVP_MAX_MD_SIZE))) {
        PyErr_SetString(PyExc_MemoryError, "hmac");
        return NULL;
    }
    HMAC(md, kbuf, klen, dbuf, dlen, blob, &blen);
    blob = PyMem_Realloc(blob, blen);
    ret = PyString_FromStringAndSize(blob, blen);
    PyMem_Free(blob);
    return ret;
}

EVP_CIPHER_CTX *cipher_ctx_new(void) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = (EVP_CIPHER_CTX *)PyMem_Malloc(sizeof(EVP_CIPHER_CTX)))) {
        PyErr_SetString(PyExc_MemoryError, "cipher_ctx_new");
    }
    /* EVP_CIPHER_CTX_init(ctx); */
    return ctx;
}

void cipher_ctx_free(EVP_CIPHER_CTX *ctx) {
    EVP_CIPHER_CTX_cleanup(ctx);
    PyMem_Free((void *)ctx);
}

PyObject *bytes_to_key(const EVP_CIPHER *cipher, EVP_MD *md, 
                        PyObject *data, PyObject *salt, PyObject *iv, int iter) {
    const void *dbuf, *sbuf, *ibuf;
    int dlen, slen, ilen, klen;
    void *key;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if ((PyObject_AsReadBuffer(data, &dbuf, &dlen) == -1)
        || (PyObject_AsReadBuffer(salt, &sbuf, &slen) == -1)
        || (PyObject_AsReadBuffer(iv, &ibuf, &ilen) == -1))
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(data)
        || !PyString_Check(salt)
        || !PyString_Check(iv)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    dlen = PyString_Size(data);
    dbuf = (const void *)PyString_AsString(data);
    slen = PyString_Size(salt);
    sbuf = (const void *)PyString_AsString(salt);
    ilen = PyString_Size(iv);
    ibuf = (const void *)PyString_AsString(iv);
#endif
    assert((slen == 8) || (slen == 0));
    if (!(key = PyMem_Malloc(cipher->key_len))) {
        PyErr_SetString(PyExc_MemoryError, "bytes_to_key");
        return NULL;
    }
    klen = EVP_BytesToKey(cipher, md, (unsigned char *)sbuf, 
        (unsigned char *)dbuf, dlen, iter, 
        (unsigned char *)key, (unsigned char*) ibuf);
    /* assert (klen == key->len); */
    ret = PyString_FromStringAndSize(key, klen);
    PyMem_Free(key);
    return ret;
}

PyObject *cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, 
                        PyObject *key, PyObject *iv, int mode) {
    const void *kbuf, *ibuf;
    int klen, ilen;

#if PYTHON_API_VERSION >= 1009
    if ((PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        || (PyObject_AsReadBuffer(iv, &ibuf, &ilen) == -1))
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(key)
        || !PyString_Check(iv)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    klen = PyString_Size(key);
    kbuf = (const void *)PyString_AsString(key);
    ilen = PyString_Size(iv);
    ibuf = (const void *)PyString_AsString(iv);
#endif
    EVP_CipherInit(ctx, cipher, (unsigned char *)kbuf, (unsigned char *)ibuf, mode);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *cipher_update(EVP_CIPHER_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len, olen;
    void *obuf;
    PyObject *ret;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    if (!(obuf = PyMem_Malloc(len + EVP_CIPHER_CTX_block_size(ctx) - 1))) {
        PyErr_SetString(PyExc_MemoryError, "cipher_update");
        return NULL;
    }
    EVP_CipherUpdate(ctx, obuf, &olen, (unsigned char *)buf, len);
    ret = PyString_FromStringAndSize(obuf, olen);
    PyMem_Free(obuf);
    return ret;
}

PyObject *cipher_final(EVP_CIPHER_CTX *ctx) {
    void *obuf;
    int olen;
    PyObject *ret;

    if (!(obuf = PyMem_Malloc(ctx->cipher->block_size))) {
        PyErr_SetString(PyExc_MemoryError, "cipher_final");
        return NULL;
    }
    EVP_CipherFinal(ctx, (unsigned char *)obuf, &olen);
    ret = PyString_FromStringAndSize(obuf, olen);
    PyMem_Free(obuf);
    return ret;
}

PyObject *sign_update(EVP_MD_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    EVP_SignUpdate(ctx, buf, len);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *sign_final(EVP_MD_CTX *ctx, EVP_PKEY *pkey) {
    unsigned char sigbuf[256]; /* XXX fixed length buffer */
    unsigned int siglen;
    PyObject *ret;

    if (!EVP_SignFinal(ctx, sigbuf, &siglen, pkey)) {
        PyErr_SetString(_evp_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    return PyString_FromStringAndSize(sigbuf, siglen);
}

PyObject *verify_update(EVP_MD_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    EVP_VerifyUpdate(ctx, buf, len);
    Py_INCREF(Py_None);
    return Py_None;
}


int verify_final(EVP_MD_CTX *ctx, PyObject *blob, EVP_PKEY *pkey) {
    unsigned char *kbuf; 
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, (const void **)&kbuf, &len) == -1)
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    len = PyString_Size(blob);
    buf = PyString_AsString(blob);
#endif
    return EVP_VerifyFinal(ctx, kbuf, len, pkey);
}

int pkey_write_pem_no_cipher(EVP_PKEY *pkey, BIO *f, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    ret = PEM_write_bio_PrivateKey(f, pkey, NULL, NULL, 0,
            passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

int pkey_write_pem(EVP_PKEY *pkey, BIO *f, EVP_CIPHER *cipher, PyObject *pyfunc) {
    int ret;

    Py_INCREF(pyfunc);
    ret = PEM_write_bio_PrivateKey(f, pkey, cipher, NULL, 0,
            passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

EVP_PKEY *pkey_read_pem(BIO *f, PyObject *pyfunc) {
    EVP_PKEY *pk;

    Py_INCREF(pyfunc);
    pk = PEM_read_bio_PrivateKey(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return pk;
}

int pkey_assign_rsa(EVP_PKEY *pkey, RSA *rsa) {
    return EVP_PKEY_assign_RSA(pkey, rsa);
}
%}

