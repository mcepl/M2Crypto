/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* 
Copyright (c) 1999 Ng Pheng Siong. All rights reserved.

Portions Copyright (c) 2004-2006 Open Source Applications Foundation.
Author: Heikki Toivonen
*/
/* $Id$ */

%{
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
%}

%apply Pointer NONNULL { EVP_MD_CTX * };
%apply Pointer NONNULL { EVP_MD * };
%apply Pointer NONNULL { EVP_PKEY * };
%apply Pointer NONNULL { HMAC_CTX * };
%apply Pointer NONNULL { EVP_CIPHER_CTX * };
%apply Pointer NONNULL { EVP_CIPHER * };
%apply Pointer NONNULL { RSA * };

%rename(md5) EVP_md5;
extern const EVP_MD *EVP_md5(void);
%rename(sha1) EVP_sha1;
extern const EVP_MD *EVP_sha1(void);
%rename(ripemd160) EVP_ripemd160;
extern const EVP_MD *EVP_ripemd160(void);

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
%rename(sha224) EVP_sha224;
extern const EVP_MD *EVP_sha224(void);
%rename(sha256) EVP_sha256;
extern const EVP_MD *EVP_sha256(void);
%rename(sha384) EVP_sha384;
extern const EVP_MD *EVP_sha384(void);
%rename(sha512) EVP_sha512;
extern const EVP_MD *EVP_sha512(void);
#endif

%rename(digest_init) EVP_DigestInit;
extern int EVP_DigestInit(EVP_MD_CTX *, const EVP_MD *);

%rename(des_ecb) EVP_des_ecb;
extern const EVP_CIPHER *EVP_des_ecb(void);
%rename(des_ede_ecb) EVP_des_ede;
extern const EVP_CIPHER *EVP_des_ede(void);
%rename(des_ede3_ecb) EVP_des_ede3;
extern const EVP_CIPHER *EVP_des_ede3(void);
%rename(des_cbc) EVP_des_cbc;
extern const EVP_CIPHER *EVP_des_cbc(void);
%rename(des_ede_cbc) EVP_des_ede_cbc;
extern const EVP_CIPHER *EVP_des_ede_cbc(void);
%rename(des_ede3_cbc) EVP_des_ede3_cbc;
extern const EVP_CIPHER *EVP_des_ede3_cbc(void);
%rename(des_cfb) EVP_des_cfb;
extern const EVP_CIPHER *EVP_des_cfb(void);
%rename(des_ede_cfb) EVP_des_ede_cfb;
extern const EVP_CIPHER *EVP_des_ede_cfb(void);
%rename(des_ede3_cfb) EVP_des_ede3_cfb;
extern const EVP_CIPHER *EVP_des_ede3_cfb(void);
%rename(des_ofb) EVP_des_ofb;
extern const EVP_CIPHER *EVP_des_ofb(void);
%rename(des_ede_ofb) EVP_des_ede_ofb;
extern const EVP_CIPHER *EVP_des_ede_ofb(void);
%rename(des_ede3_ofb) EVP_des_ede3_ofb;
extern const EVP_CIPHER *EVP_des_ede3_ofb(void);
%rename(bf_ecb) EVP_bf_ecb;
extern const EVP_CIPHER *EVP_bf_ecb(void);
%rename(bf_cbc) EVP_bf_cbc;
extern const EVP_CIPHER *EVP_bf_cbc(void);
%rename(bf_cfb) EVP_bf_cfb;
extern const EVP_CIPHER *EVP_bf_cfb(void);
%rename(bf_ofb) EVP_bf_ofb;
extern const EVP_CIPHER *EVP_bf_ofb(void);
/*
%rename(idea_ecb) extern const EVP_CIPHER *EVP_idea_ecb(void);
%rename(idea_cbc) extern const EVP_CIPHER *EVP_idea_cbc(void);
%rename(idea_cfb) extern const EVP_CIPHER *EVP_idea_cfb(void);
%rename(idea_ofb) extern const EVP_CIPHER *EVP_idea_ofb(void);
*/
%rename(cast5_ecb) EVP_cast5_ecb;
extern const EVP_CIPHER *EVP_cast5_ecb(void);
%rename(cast5_cbc) EVP_cast5_cbc;
extern const EVP_CIPHER *EVP_cast5_cbc(void);
%rename(cast5_cfb) EVP_cast5_cfb;
extern const EVP_CIPHER *EVP_cast5_cfb(void);
%rename(cast5_ofb) EVP_cast5_ofb;
extern const EVP_CIPHER *EVP_cast5_ofb(void);
/*
%rename(rc5_ecb) extern const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
%rename(rc5_cbc) extern const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
%rename(rc5_cfb) extern const EVP_CIPHER *EVP_rc5_32_12_16_cfb(void);
%rename(rc5_ofb) extern const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
*/
%rename(rc4) EVP_rc4;
extern const EVP_CIPHER *EVP_rc4(void);
%rename(rc2_40_cbc) EVP_rc2_40_cbc;
extern const EVP_CIPHER *EVP_rc2_40_cbc(void);
%rename(aes_128_ecb) EVP_aes_128_ecb;
extern const EVP_CIPHER *EVP_aes_128_ecb(void);
%rename(aes_128_cbc) EVP_aes_128_cbc;
extern const EVP_CIPHER *EVP_aes_128_cbc(void);
%rename(aes_128_cfb) EVP_aes_128_cfb;
extern const EVP_CIPHER *EVP_aes_128_cfb(void);
%rename(aes_128_ofb) EVP_aes_128_ofb;
extern const EVP_CIPHER *EVP_aes_128_ofb(void);
%rename(aes_192_ecb) EVP_aes_192_ecb;
extern const EVP_CIPHER *EVP_aes_192_ecb(void);
%rename(aes_192_cbc) EVP_aes_192_cbc;
extern const EVP_CIPHER *EVP_aes_192_cbc(void);
%rename(aes_192_cfb) EVP_aes_192_cfb;
extern const EVP_CIPHER *EVP_aes_192_cfb(void);
%rename(aes_192_ofb) EVP_aes_192_ofb;
extern const EVP_CIPHER *EVP_aes_192_ofb(void);
%rename(aes_256_ecb) EVP_aes_256_ecb;
extern const EVP_CIPHER *EVP_aes_256_ecb(void);
%rename(aes_256_cbc) EVP_aes_256_cbc;
extern const EVP_CIPHER *EVP_aes_256_cbc(void);
%rename(aes_256_cfb) EVP_aes_256_cfb;
extern const EVP_CIPHER *EVP_aes_256_cfb(void);
%rename(aes_256_ofb) EVP_aes_256_ofb;
extern const EVP_CIPHER *EVP_aes_256_ofb(void);

%rename(pkey_new) EVP_PKEY_new;
extern EVP_PKEY *EVP_PKEY_new(void);
%rename(pkey_free) EVP_PKEY_free;
extern void EVP_PKEY_free(EVP_PKEY *);
%rename(pkey_assign) EVP_PKEY_assign;
extern int EVP_PKEY_assign(EVP_PKEY *, int, char *);
%rename(pkey_set1_rsa) EVP_PKEY_set1_RSA;
extern int EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);
%rename(pkey_get1_rsa) EVP_PKEY_get1_RSA;
extern RSA* EVP_PKEY_get1_RSA(EVP_PKEY *);
%rename(sign_init) EVP_SignInit;
extern int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
%rename(verify_init) EVP_VerifyInit;
extern int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);
%rename(pkey_size) EVP_PKEY_size;
extern int EVP_PKEY_size(EVP_PKEY *);

%inline %{
#define PKCS5_SALT_LEN  8

static PyObject *_evp_err;

void evp_init(PyObject *evp_err) {
    Py_INCREF(evp_err);
    _evp_err = evp_err;
}

EVP_MD_CTX *md_ctx_new(void) {
    EVP_MD_CTX *ctx;

    if (!(ctx = EVP_MD_CTX_create())) {
        PyErr_SetString(PyExc_MemoryError, "md_ctx_new");
    }
    return ctx;
}

void md_ctx_free(EVP_MD_CTX *ctx) {
    EVP_MD_CTX_destroy(ctx);
}

int digest_update(EVP_MD_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return -1;

    return EVP_DigestUpdate(ctx, buf, (unsigned int)len);
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
        return NULL;
    }
    HMAC_CTX_init(ctx);
    return ctx;
}

void hmac_ctx_free(HMAC_CTX *ctx) {
    HMAC_CTX_cleanup(ctx);
    PyMem_Free((void *)ctx);
}

PyObject *hmac_init(HMAC_CTX *ctx, PyObject *key, const EVP_MD *md) {
    const void *kbuf;
    int klen;

    if (PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        return NULL;

    HMAC_Init(ctx, kbuf, klen, md);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *hmac_update(HMAC_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;

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

    if ((PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        || (PyObject_AsReadBuffer(data, &dbuf, &dlen) == -1))
        return NULL;

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
        return NULL;
    }
    EVP_CIPHER_CTX_init(ctx);
    return ctx;
}

void cipher_ctx_free(EVP_CIPHER_CTX *ctx) {
    EVP_CIPHER_CTX_cleanup(ctx);
    PyMem_Free((void *)ctx);
}

PyObject *bytes_to_key(const EVP_CIPHER *cipher, EVP_MD *md, 
                        PyObject *data, PyObject *salt,
                        PyObject *iv, /* Not used */
                        int iter) {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    const void *dbuf, *sbuf;
    int dlen, slen, klen;
    PyObject *ret;

    if ((PyObject_AsReadBuffer(data, &dbuf, &dlen) == -1)
        || (PyObject_AsReadBuffer(salt, &sbuf, &slen) == -1))
        return NULL;

    assert((slen == 8) || (slen == 0));
    klen = EVP_BytesToKey(cipher, md, (unsigned char *)sbuf, 
        (unsigned char *)dbuf, dlen, iter, 
        key, NULL); /* Since we are not returning IV no need to derive it */
    ret = PyString_FromStringAndSize(key, klen);
    return ret;
}

PyObject *cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, 
                        PyObject *key, PyObject *iv, int mode) {
    const void *kbuf, *ibuf;
    int klen, ilen;

    if ((PyObject_AsReadBuffer(key, &kbuf, &klen) == -1)
        || (PyObject_AsReadBuffer(iv, &ibuf, &ilen) == -1))
        return NULL;

    EVP_CipherInit(ctx, cipher, (unsigned char *)kbuf, (unsigned char *)ibuf, mode);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *cipher_update(EVP_CIPHER_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len, olen;
    void *obuf;
    PyObject *ret;

    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;

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

    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;

    EVP_SignUpdate(ctx, buf, len);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *sign_final(EVP_MD_CTX *ctx, EVP_PKEY *pkey) {
    unsigned char sigbuf[256]; /* XXX fixed length buffer */
    unsigned int siglen;

    if (!EVP_SignFinal(ctx, sigbuf, &siglen, pkey)) {
        PyErr_SetString(_evp_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    return PyString_FromStringAndSize(sigbuf, siglen);
}

int verify_update(EVP_MD_CTX *ctx, PyObject *blob) {
    const void *buf;
    int len;

    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return -1;

    return EVP_VerifyUpdate(ctx, buf, len);
}


int verify_final(EVP_MD_CTX *ctx, PyObject *blob, EVP_PKEY *pkey) {
    unsigned char *kbuf; 
    int len;

    if (PyObject_AsReadBuffer(blob, (const void **)&kbuf, &len) == -1)
        return -1;

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

PyObject * pkey_as_der(EVP_PKEY *pkey){
    unsigned char * pp = NULL;
    int len;
    PyObject * der;
    len = i2d_PUBKEY(pkey, &pp);
    if (len < 0){
        PyErr_SetString(PyExc_ValueError, "EVP_PKEY as DER failed");
        return NULL; 
    }
    der = PyString_FromStringAndSize(/*(void *)*/ pp, len);
    OPENSSL_free(pp);
    return der;
}

PyObject *pkey_get_modulus(EVP_PKEY *pkey)
{
    RSA *rsa;
    DSA *dsa;
    BIO *bio;
    BUF_MEM *bptr;
    PyObject *ret;

    switch (pkey->type) {
        case EVP_PKEY_RSA:
            rsa = EVP_PKEY_get1_RSA(pkey);

            bio = BIO_new(BIO_s_mem());
            if (!bio) {
                PyErr_SetString(PyExc_MemoryError, "pkey_get_modulus");
                return NULL;
            }
            
            if (!BN_print(bio, rsa->n)) {
                PyErr_SetString(PyExc_RuntimeError, 
                      ERR_error_string(ERR_get_error(), NULL));
                BIO_free(bio);
                return NULL;
            }
            BIO_get_mem_ptr(bio, &bptr);
            ret = PyString_FromStringAndSize(bptr->data, bptr->length);
            BIO_set_close(bio, BIO_CLOSE);
            BIO_free(bio);

            break;

        case EVP_PKEY_DSA:
            dsa = EVP_PKEY_get1_DSA(pkey);

            bio = BIO_new(BIO_s_mem());
            if (!bio) {
                PyErr_SetString(PyExc_MemoryError, "pkey_get_modulus");
                return NULL;
            }

            if (!BN_print(bio, dsa->pub_key)) {
                PyErr_SetString(PyExc_RuntimeError, 
                      ERR_error_string(ERR_get_error(), NULL));
                BIO_free(bio);
                return NULL;
            }
            BIO_get_mem_ptr(bio, &bptr);
            ret = PyString_FromStringAndSize(bptr->data, bptr->length);
            BIO_set_close(bio, BIO_CLOSE);
            BIO_free(bio);

            break;
            
        default:
            PyErr_SetString(PyExc_ValueError, "unsupported key type");
            return NULL;
    }
    
    return ret;
}


%}

