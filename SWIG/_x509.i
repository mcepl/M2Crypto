/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.  */
/*
** Portions created by Open Source Applications Foundation (OSAF) are
** Copyright (C) 2004-2005 OSAF. All Rights Reserved.
*/
/* $Id$   */

%{
#include <openssl/x509.h>
#include <openssl/x509v3.h>
%}

%apply Pointer NONNULL { BIO * };
%apply Pointer NONNULL { X509 * };
%apply Pointer NONNULL { X509_CRL * };
%apply Pointer NONNULL { X509_REQ * };
%apply Pointer NONNULL { X509_NAME * };
%apply Pointer NONNULL { X509_NAME_ENTRY * };
%apply Pointer NONNULL { EVP_PKEY * };

%name(x509_new) extern X509 *X509_new( void );
%name(x509_dup) extern X509 *X509_dup(X509 *);
%name(x509_free) extern void X509_free(X509 *);
%name(x509_crl_free) extern void X509_CRL_free(X509_CRL *);

%name(x509_print) extern int X509_print(BIO *, X509 *);
%name(x509_crl_print) extern int X509_CRL_print(BIO *, X509_CRL *);

%name(x509_get_serial_number) extern ASN1_INTEGER *X509_get_serialNumber(X509 *);
%name(x509_set_serial_number) extern int X509_set_serialNumber(X509 *, ASN1_INTEGER *);
%name(x509_get_pubkey) extern EVP_PKEY *X509_get_pubkey(X509 *);
%name(x509_set_pubkey) extern int X509_set_pubkey(X509 *, EVP_PKEY *);
%name(x509_get_issuer_name) extern X509_NAME *X509_get_issuer_name(X509 *);
%name(x509_set_issuer_name) extern int X509_set_issuer_name(X509 *, X509_NAME *);
%name(x509_get_subject_name) extern X509_NAME *X509_get_subject_name(X509 *);
%name(x509_set_subject_name) extern int X509_set_subject_name(X509 *, X509_NAME *);

/* From x509.h */
/* standard trust ids */
%constant int X509_TRUST_DEFAULT      = -1;
%constant int X509_TRUST_COMPAT       = 1;
%constant int X509_TRUST_SSL_CLIENT   = 2;
%constant int X509_TRUST_SSL_SERVER   = 3;
%constant int X509_TRUST_EMAIL        = 4;
%constant int X509_TRUST_OBJECT_SIGN  = 5;
%constant int X509_TRUST_OCSP_SIGN    = 6;
%constant int X509_TRUST_OCSP_REQUEST = 7;

/* trust_flags values */
%constant int X509_TRUST_DYNAMIC      = 1;
%constant int X509_TRUST_DYNAMIC_NAME = 2;

/* check_trust return codes */
%constant int X509_TRUST_TRUSTED      = 1;
%constant int X509_TRUST_REJECTED     = 2;
%constant int X509_TRUST_UNTRUSTED    = 3;

/* From x509v3.h */
%constant int X509_PURPOSE_SSL_CLIENT         = 1;
%constant int X509_PURPOSE_SSL_SERVER         = 2;
%constant int X509_PURPOSE_NS_SSL_SERVER      = 3;
%constant int X509_PURPOSE_SMIME_SIGN         = 4;
%constant int X509_PURPOSE_SMIME_ENCRYPT      = 5;
%constant int X509_PURPOSE_CRL_SIGN           = 6;
%constant int X509_PURPOSE_ANY                = 7;
%constant int X509_PURPOSE_OCSP_HELPER        = 8;

/*%name(x509_check_ca) extern int X509_check_ca(X509 *);*/
%name(x509_check_purpose) extern X509_check_purpose(X509 *, int, int);
%name(x509_check_trust) extern X509_check_trust(X509 *, int, int);

%name(x509_write_pem) extern int PEM_write_bio_X509(BIO *, X509 *);
%name(x509_write_pem_file) extern int PEM_write_X509(FILE *, X509 *);

%name(x509_verify) extern int X509_verify(X509 *a, EVP_PKEY *r);
%name(x509_get_verify_error) extern const char *X509_verify_cert_error_string(long);

%name(x509_add_ext) extern int X509_add_ext(X509 *, X509_EXTENSION *, int);
%name(x509_get_ext_count) extern int X509_get_ext_count(X509 *);
%name(x509_get_ext) extern X509_EXTENSION *X509_get_ext(X509 *, int);
%name(x509_ext_print) extern int X509V3_EXT_print(BIO *, X509_EXTENSION *, unsigned long, int);

%name(x509_name_new) extern X509_NAME *X509_NAME_new( void );
%name(x509_name_free) extern void X509_NAME_free(X509_NAME *);
%name(x509_name_print) extern int X509_NAME_print(BIO *, X509_NAME *, int);
%name(x509_name_get_entry) extern X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *, int);
%name(x509_name_entry_count) extern int X509_NAME_entry_count(X509_NAME *);
%name(x509_name_delete_entry) extern X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *, int);
%name(x509_name_add_entry) extern int X509_NAME_add_entry(X509_NAME *, X509_NAME_ENTRY *, int, int);
%name(x509_name_add_entry_by_obj) extern int X509_NAME_add_entry_by_OBJ(X509_NAME *, ASN1_OBJECT *, int, unsigned char *, int, int, int );
%name(x509_name_add_entry_by_nid) extern int X509_NAME_add_entry_by_NID(X509_NAME *, int, int, unsigned char *, int, int, int );
%name(x509_name_print_ex) extern int X509_NAME_print_ex(BIO *, X509_NAME *, int, unsigned long);
%name(x509_name_print_ex_fp) extern int X509_NAME_print_ex_fp(FILE *, X509_NAME *, int, unsigned long);

%name(x509_name_entry_new) extern X509_NAME_ENTRY *X509_NAME_ENTRY_new( void );
%name(x509_name_entry_free) extern void X509_NAME_ENTRY_free( X509_NAME_ENTRY *);
%name(x509_name_entry_create_by_nid) extern X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID( X509_NAME_ENTRY **, int, int, unsigned char *, int);
%name(x509_name_entry_set_object) extern int X509_NAME_ENTRY_set_object( X509_NAME_ENTRY *, ASN1_OBJECT *);
%name(x509_name_entry_set_data) extern int X509_NAME_ENTRY_set_data( X509_NAME_ENTRY *, int, CONST unsigned char *, int);
%name(x509_name_entry_get_object) extern ASN1_OBJECT *X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *);
%name(x509_name_entry_get_data) extern ASN1_STRING *X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *);

%name(x509_req_new) extern X509_REQ * X509_REQ_new();
%name(x509_req_free) extern void X509_REQ_free(X509_REQ *);
%name(x509_req_print) extern int X509_REQ_print(BIO *, X509_REQ *);

%name(x509_req_get_pubkey) extern EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *);
%name(x509_req_set_pubkey) extern int X509_REQ_set_pubkey(X509_REQ *, EVP_PKEY *);
%name(x509_req_set_subject_name) extern int X509_REQ_set_subject_name(X509_REQ *, X509_NAME *);

%name(x509_req_verify) extern int X509_REQ_verify(X509_REQ *, EVP_PKEY *);
%name(x509_req_sign) extern int X509_REQ_sign(X509_REQ *, EVP_PKEY *, const EVP_MD *);

%name(i2d_x509) extern int i2d_X509_bio(BIO *, X509 *);

%name(x509_store_new) extern X509_STORE *X509_STORE_new(void);
%name(x509_store_free) extern void X509_STORE_free(X509_STORE *);
%name(x509_store_add_cert) extern int X509_STORE_add_cert(X509_STORE *, X509 *);

%name(x509_store_ctx_get_current_cert) extern X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *);
%name(x509_store_ctx_get_error) extern int X509_STORE_CTX_get_error(X509_STORE_CTX *);
%name(x509_store_ctx_get_error_depth) extern int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *);
%name(x509_store_ctx_free) extern void X509_STORE_CTX_free(X509_STORE_CTX *);

%name(x509_extension_get_critical) extern int X509_EXTENSION_get_critical(X509_EXTENSION *);
%name(x509_extension_set_critical) extern int X509_EXTENSION_set_critical(X509_EXTENSION *, int);

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

/* Cribbed from rsa.h. */
%constant int RSA_3                           = 0x3L;
%constant int RSA_F4                          = 0x10001L;

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

/* X509_set_version() is a macro. */
int x509_set_version(X509 *x, long version) {
    return X509_set_version(x, version);
}

/* X509_get_version() is a macro. */
long x509_get_version(X509 *x) {
    return X509_get_version(x);
}

/* X509_set_notBefore() is a macro. */
int x509_set_not_before(X509 *x, ASN1_UTCTIME *tm) {
    return X509_set_notBefore(x, tm);
}

/* X509_get_notBefore() is a macro. */
ASN1_UTCTIME *x509_get_not_before(X509 *x) {
    return X509_get_notBefore(x);
}

/* X509_set_notAfter() is a macro. */
int x509_set_not_after(X509 *x, ASN1_UTCTIME *tm) {
    return X509_set_notAfter(x, tm);
}

/* X509_get_notAfter() is a macro. */
ASN1_UTCTIME *x509_get_not_after(X509 *x) {
    return X509_get_notAfter(x);
}

int x509_sign(X509 *x, EVP_PKEY *pkey, EVP_MD *md) {
    return X509_sign(x, pkey, md);
}

/* XXX The first parameter is really ASN1_TIME, does it matter? */
ASN1_TIME *x509_gmtime_adj(ASN1_UTCTIME *s, long adj) {
    return X509_gmtime_adj(s, adj);
}

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

/* x509_name_add_entry_by_txt */
int x509_name_add_entry_by_txt(X509_NAME *name, char *field, int type, char *bytes, int len, int loc, int set) {
	return X509_NAME_add_entry_by_txt( name, (unsigned char *)field, type, (char *)bytes, len, loc, set);
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

long x509_req_get_version(X509_REQ *x) {
    return X509_REQ_get_version(x);
}

int x509_req_set_version(X509_REQ *x, long version) {
    return X509_REQ_set_version(x, version);
}

int x509_req_add_extensions(X509_REQ *req, STACK *exts) {
    return X509_REQ_add_extensions(req, (STACK_OF(X509_EXTENSION) *)exts);
}

X509_NAME_ENTRY *x509_name_entry_create_by_txt( X509_NAME_ENTRY **ne, char *field, int type, unsigned char *bytes, int len) {
	return X509_NAME_ENTRY_create_by_txt( ne, field, type, bytes, len);
}

X509_EXTENSION *x509v3_ext_conf(LHASH *conf, X509V3_CTX *ctx, char *name, char *value) {
    return X509V3_EXT_conf(conf, ctx, name, value);
}

/* X509_EXTENSION_free() might be a macro, didn't find definition. */
void x509_extension_free(X509_EXTENSION *ext) {
    X509_EXTENSION_free(ext);
}

char *x509_extension_get_name(X509_EXTENSION *ext) {
    return strdup(OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext))));
}

/* sk_X509_EXTENSION_new_null is a macro. */
STACK *sk_x509_extension_new_null(void) {
    return (STACK *)sk_X509_EXTENSION_new_null();
}

/* sk_X509_EXTENSION_free() is a macro. */
void sk_x509_extension_free(STACK *stack) {
    sk_X509_EXTENSION_free((STACK_OF(X509_EXTENSION) *)stack);
}

/* sk_X509_EXTENSION_push() is a macro. */
int sk_x509_extension_push(STACK *stack, X509_EXTENSION *x509_ext) {
    return sk_X509_EXTENSION_push((STACK_OF(X509_EXTENSION) *)stack, x509_ext);
}

/* sk_X509_EXTENSION_pop() is a macro. */
X509_EXTENSION *sk_x509_extension_pop(STACK *stack) {
    return sk_X509_EXTENSION_pop((STACK_OF(X509_EXTENSION) *)stack);
}

/* sk_X509_EXTENSION_num() is a macro. */
int sk_x509_extension_num(STACK *stack) {
    return sk_X509_EXTENSION_num((STACK_OF(X509_EXTENSION) *)stack);
}

/* sk_X509_EXTENSION_value() is a macro. */
X509_EXTENSION *sk_x509_extension_value(STACK *stack, int i) {
    return sk_X509_EXTENSION_value((STACK_OF(X509_EXTENSION) *)stack, i);
}

/* X509_STORE_CTX_get_app_data is a macro. */
void *x509_store_ctx_get_app_data(X509_STORE_CTX *ctx) {
  return X509_STORE_CTX_get_app_data(ctx);
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
