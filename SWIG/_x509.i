/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved.  */
/* $Id: _x509.i,v 1.1 2003/06/22 17:30:52 ngps Exp $   */

%{
#include <openssl/x509.h>
%}

%apply Pointer NONNULL { BIO * };
%apply Pointer NONNULL { X509 * };
%apply Pointer NONNULL { X509_CRL * };
%apply Pointer NONNULL { X509_NAME * };
%apply Pointer NONNULL { X509_REQ * };

%name(x509_free) extern void X509_free(X509 *);
%name(x509_req_new) extern X509_REQ * X509_REQ_new();
%name(x509_req_free) extern void X509_REQ_free(X509_REQ *);
%name(x509_crl_free) extern void X509_CRL_free(X509_CRL *);
%name(x509_name_free) extern void X509_NAME_free(X509_NAME *);

%name(x509_print) extern int X509_print(BIO *, X509 *);
%name(x509_req_print) extern int X509_REQ_print(BIO *, X509_REQ *);
%name(x509_crl_print) extern int X509_CRL_print(BIO *, X509_CRL *);

%name(x509_get_serial_number) extern ASN1_INTEGER *X509_get_serialNumber(X509 *);
%name(x509_get_pubkey) extern EVP_PKEY *X509_get_pubkey(X509 *);
%name(x509_get_issuer_name) extern X509_NAME *X509_get_issuer_name(X509 *);
%name(x509_get_subject_name) extern X509_NAME *X509_get_subject_name(X509 *);

%name(x509_get_verify_error) extern const char *X509_verify_cert_error_string(long);

%name(x509_req_set_pubkey) extern int X509_REQ_set_pubkey(X509_REQ *, EVP_PKEY *);

%name(i2d_x509) extern int i2d_X509_bio(BIO *, X509 *);

%name(x509_store_new) extern X509_STORE *X509_STORE_new(void);
%name(x509_store_free) extern void X509_STORE_free(X509_STORE *);
%name(x509_store_add_cert) extern int X509_STORE_add_cert(X509_STORE *, X509 *);

%constant int NID_commonName                  = 13;
%constant int NID_countryName                 = 14;
%constant int NID_localityName                = 15;
%constant int NID_stateOrProvinceName         = 16;
%constant int NID_organizationName            = 17;
%constant int NID_organizationalUnitName      = 18;
%constant int NID_pkcs9_emailAddress          = 48;

/* Cribbed from x509_vfy.h. */
%constant int		X509_V_OK					= 0;
%constant int		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT		= 2;
%constant int		X509_V_ERR_UNABLE_TO_GET_CRL			= 3;
%constant int		X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE	= 4;
%constant int		X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE	= 5;
%constant int		X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY	= 6;
%constant int		X509_V_ERR_CERT_SIGNATURE_FAILURE		= 7;
%constant int		X509_V_ERR_CRL_SIGNATURE_FAILURE		= 8;
%constant int		X509_V_ERR_CERT_NOT_YET_VALID			= 9;
%constant int		X509_V_ERR_CERT_HAS_EXPIRED			= 10;
%constant int		X509_V_ERR_CRL_NOT_YET_VALID			= 11;
%constant int		X509_V_ERR_CRL_HAS_EXPIRED			= 12;
%constant int		X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD	= 13;
%constant int		X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD	= 14;
%constant int		X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD	= 15;
%constant int		X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD	= 16;
%constant int		X509_V_ERR_OUT_OF_MEM				= 17;
%constant int		X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT		= 18;
%constant int		X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN		= 19;
%constant int		X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY	= 20;
%constant int		X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE	= 21;
%constant int		X509_V_ERR_CERT_CHAIN_TOO_LONG			= 22;
%constant int		X509_V_ERR_CERT_REVOKED				= 23;
%constant int		X509_V_ERR_INVALID_CA				= 24;
%constant int		X509_V_ERR_PATH_LENGTH_EXCEEDED			= 25;
%constant int		X509_V_ERR_INVALID_PURPOSE			= 26;
%constant int		X509_V_ERR_CERT_UNTRUSTED			= 27;
%constant int		X509_V_ERR_CERT_REJECTED			= 28;
%constant int		X509_V_ERR_APPLICATION_VERIFICATION		= 50;

%inline %{
static PyObject *_x509_err;

void x509_init(PyObject *x509_err) {
    Py_INCREF(x509_err);
    _x509_err = x509_err;
}

X509 *x509_read_pem(BIO *bio) {
    return PEM_read_bio_X509(bio, NULL, NULL, NULL);
}

X509_REQ *x509_req_read_pem(BIO *bio) {
    return PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
}

int x509_req_write_pem(BIO *bio, X509_REQ *x) {
    return PEM_write_bio_X509_REQ(bio, x);
}

X509_CRL *x509_crl_read_pem(BIO *bio) {
    return PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
}

/* X509_get_version() is a macro. */
long x509_get_version(X509 *x) {
    return X509_get_version(x);
}

/* X509_get_notBefore() is a macro. */
ASN1_UTCTIME *x509_get_not_before(X509 *x) {
    return X509_get_notBefore(x);
}

/* X509_get_notAfter() is a macro. */
ASN1_UTCTIME *x509_get_not_after(X509 *x) {
    return X509_get_notAfter(x);
}

/*
Blob *x509_name_by_nid(X509_NAME *name, int nid) {
    Blob *blob;
    int buflen;

    buflen = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
    if (buflen == -1) {
        return NULL;
    }
    blob = blob_new(buflen+1, "x509_name_by_nid");
    buflen = X509_NAME_get_text_by_NID(name, nid, blob->data, blob->len);
    if (buflen != blob->len) { 
        blob->data = (unsigned char *)realloc(blob->data, buflen);
        blob->len = buflen;
        }
    return blob;
}
*/

PyObject *x509_name_by_nid(X509_NAME *name, int nid) {
    void *buf;
    int len, xlen;
    PyObject *ret;

    if ((len = X509_NAME_get_text_by_NID(name, nid, NULL, 0)) == -1) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    len++;
    if (!(buf = PyMem_Malloc(len))) {
        PyErr_SetString(PyExc_MemoryError, "x509_name_by_nid");
        return NULL;
    }
    xlen = X509_NAME_get_text_by_NID(name, nid, buf, len);
    ret = PyString_FromStringAndSize(buf, xlen);
    PyMem_Free(buf);
    return ret;
}

int x509_name_set_by_nid(X509_NAME *name, int nid, PyObject *obj) {
    return X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC, PyString_AsString(obj), -1, -1, 0);
}

/* sk_X509_new_null() is a macro returning "STACK_OF(X509) *". */
STACK *sk_x509_new_null(void) {
    return (STACK *)sk_X509_new_null();
}

/* sk_X509_free() is a macro. */
void sk_x509_free(STACK *stack) {
    sk_X509_free((STACK_OF(X509) *)stack);
}

/* sk_X509_push() is a macro. */
int sk_x509_push(STACK *stack, X509 *x509) {
    return sk_X509_push((STACK_OF(X509) *)stack, x509);
}

/* sk_X509_pop() is a macro. */
X509 *sk_x509_pop(STACK *stack) {
    return sk_X509_pop((STACK_OF(X509) *)stack);
}

int x509_store_load_locations(X509_STORE *store, const char *file) {
    return X509_STORE_load_locations(store, file, NULL);
}

int x509_type_check(X509 *x509) {
    return 1;
}

int x509_name_type_check(X509_NAME *name) {
    return 1;
}

X509_NAME *x509_req_get_subject_name(X509_REQ *x) {
    return X509_REQ_get_subject_name(x);
}

int x509_req_sign(X509_REQ *x, EVP_PKEY *pkey, EVP_MD *md) {
    return X509_REQ_sign(x, pkey, md);
}
%}

/* Free malloc'ed return value for x509_name_oneline */
%typemap(python, ret) char * {
    if ($1 != NULL)
        free($1);
}
%inline %{
char *x509_name_oneline(X509_NAME *x) {
    return X509_NAME_oneline(x, NULL, 0);
}
%}
%typemap(python, ret) char *;
