/* Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>

PyObject *dsa_sig_get_r(DSA_SIG *dsa_sig) {
    return bn_to_mpi(dsa_sig->r);
}

PyObject *dsa_sig_get_s(DSA_SIG *dsa_sig) {
    return bn_to_mpi(dsa_sig->s);
}
%}

%apply Pointer NONNULL { DSA * };

%name(dsa_new) extern DSA *DSA_new(void);
%name(dsa_free) extern void DSA_free(DSA *);
%name(dsa_size) extern int DSA_size(const DSA *); /* assert(dsa->q); */
%name(dsa_gen_key) extern int DSA_generate_key(DSA *);

%inline %{
static PyObject *_dsa_err;

void dsa_init(PyObject *dsa_err) {
    Py_INCREF(dsa_err);
    _dsa_err = dsa_err;
}

void genparam_callback(int p, int n, void *arg) {
    PyObject *argv, *ret, *cbfunc;

    cbfunc = (PyObject *)arg; 
    argv = Py_BuildValue("(ii)", p, n);
    ret = PyEval_CallObject(cbfunc, argv);
    PyErr_Clear();
    Py_DECREF(argv);
    Py_XDECREF(ret);
}

DSA *dsa_generate_parameters(int bits, PyObject *pyfunc) {
    DSA *dsa;

    Py_INCREF(pyfunc);
    dsa = DSA_generate_parameters(bits, NULL, 0, NULL, NULL, genparam_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    if (!dsa)
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
    return dsa;
}

PyObject *dsa_get_p(DSA *dsa) {
    if (!dsa->p) {
        PyErr_SetString(_dsa_err, "'p' is unset");
        return NULL;
    }
    return bn_to_mpi(dsa->p);
}

PyObject *dsa_get_q(DSA *dsa) {
    if (!dsa->q) {
        PyErr_SetString(_dsa_err, "'q' is unset");
        return NULL;
    }
    return bn_to_mpi(dsa->q);
}

PyObject *dsa_get_g(DSA *dsa) {
    if (!dsa->g) {
        PyErr_SetString(_dsa_err, "'g' is unset");
        return NULL;
    }
    return bn_to_mpi(dsa->g);
}

PyObject *dsa_get_pub(DSA *dsa) {
    if (!dsa->pub_key) {
        PyErr_SetString(_dsa_err, "'pub' is unset");
        return NULL;
    }
    return bn_to_mpi(dsa->pub_key);
}

PyObject *dsa_get_priv(DSA *dsa) {
    if (!dsa->priv_key) {
        PyErr_SetString(_dsa_err, "'priv' is unset");
        return NULL;
    }
    return bn_to_mpi(dsa->priv_key);
}

PyObject *dsa_set_p(DSA *dsa, PyObject *value) {
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
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (dsa->p)
        BN_free(dsa->p);
    dsa->p = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *dsa_set_q(DSA *dsa, PyObject *value) {
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
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (dsa->q)
        BN_free(dsa->q);
    dsa->q = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *dsa_set_g(DSA *dsa, PyObject *value) {
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
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (dsa->g)
        BN_free(dsa->g);
    dsa->g = bn;
    Py_INCREF(Py_None);
    return Py_None;
}

DSA *dsa_read_params(BIO *f, PyObject *pyfunc) {
    DSA *ret;

    Py_INCREF(pyfunc);
    ret = PEM_read_bio_DSAparams(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

DSA *dsa_read_key(BIO *f, PyObject *pyfunc) {
    DSA *ret;

    Py_INCREF(pyfunc);
    ret = PEM_read_bio_DSAPrivateKey(f, NULL, passphrase_callback, (void *)pyfunc);
    Py_DECREF(pyfunc);
    return ret;
}

/* Deprecated.
PyObject *dsa_sign(DSA *dsa, Blob *digest) {
    PyObject *pytuple;
    DSA_SIG *sig; 

    if (!(sig=DSA_do_sign(digest->data, digest->len, dsa))) {
        PyErr_SetString(PyExc_RuntimeError, 
            ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    if (!(pytuple=PyTuple_New(2))) {
        PyErr_SetString(PyExc_RuntimeError, "PyTuple_New() fails");
        return NULL;
    }
    PyTuple_SET_ITEM(pytuple, 0, dsa_sig_get_r(sig));
    PyTuple_SET_ITEM(pytuple, 1, dsa_sig_get_s(sig));
    return pytuple;
}
*/

PyObject *dsa_sign(DSA *dsa, PyObject *value) {
    const void *vbuf;
    int vlen;
    PyObject *tuple;
    DSA_SIG *sig; 

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
    if (!(sig = DSA_do_sign(vbuf, vlen, dsa))) {
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    if (!(tuple = PyTuple_New(2))) {
        PyErr_SetString(_dsa_err, "unable to create tuple");
        return NULL;
    }
    PyTuple_SET_ITEM(tuple, 0, dsa_sig_get_r(sig));
    PyTuple_SET_ITEM(tuple, 1, dsa_sig_get_s(sig));
    return tuple;
}

int dsa_verify(DSA *dsa, PyObject *value, PyObject *r, PyObject *s) {
    const void *vbuf, *rbuf, *sbuf;
    int vlen, rlen, slen;
    DSA_SIG *sig;
    int ret;

#if PYTHON_API_VERSION >= 1009
    if ((PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        || (PyObject_AsReadBuffer(r, &rbuf, &rlen) == -1)
        || (PyObject_AsReadBuffer(s, &sbuf, &slen) == -1))
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if ((!PyString_Check(value)) 
        || (!PyString_Check(r)) 
        || (!PyString_Check(s))) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    vlen = PyString_Size(value);
    vbuf = (const void *)PyString_AsString(value);
    rlen = PyString_Size(r);
    rbuf = (const void *)PyString_AsString(r);
    slen = PyString_Size(s);
    sbuf = (const void *)PyString_AsString(s);
#endif
    if (!(sig = DSA_SIG_new())) {
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        return -1;
    }
    if (!(sig->r = BN_mpi2bn((unsigned char *)rbuf, rlen, NULL))) {
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        DSA_SIG_free(sig);
        return -1;
    }
    if (!(sig->s = BN_mpi2bn((unsigned char *)sbuf, slen, NULL))) {
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        DSA_SIG_free(sig);
        return -1;
    }
    ret = DSA_do_verify(vbuf, vlen, sig, dsa);
    DSA_SIG_free(sig);
    if (ret == -1)
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
    return ret;
}

/*
Blob *dsa_sign_asn1(DSA *dsa, Blob *digest) {
        Blob *sig; 
        unsigned char sigbuf[256];
        unsigned int siglen;

        if (!DSA_sign(0, digest->data, digest->len, sigbuf, &siglen, dsa)) {
                PyErr_SetString(PyExc_RuntimeError, 
                        ERR_error_string(ERR_get_error(), NULL));
                return NULL;
        }
        if ((sig=(Blob *)malloc(sizeof(Blob)))==NULL) {
                PyErr_SetString(PyExc_MemoryError, "dsa_sign");
                return NULL;
        }
        if ((sig->data=(unsigned char *)malloc(siglen))==NULL) {
        free(sig);
                PyErr_SetString(PyExc_MemoryError, "dsa_sign");
                return NULL;
        }
        sig->len=siglen;
        strncpy((char *)sig->data, (const char *)sigbuf, siglen);
        return sig;
}
*/

PyObject *dsa_sign_asn1(DSA *dsa, PyObject *value) {
    const void *vbuf;
    int vlen;
    void *sigbuf;
    int siglen;
    PyObject *ret;

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
    if (!(sigbuf = PyMem_Malloc(DSA_size(dsa)))) {
        PyErr_SetString(PyExc_MemoryError, "dsa_sign_asn1");
        return NULL;
    }
    if (!DSA_sign(0, vbuf, vlen, (unsigned char *)sigbuf, &siglen, dsa)) {
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
        PyMem_Free(sigbuf);
        return NULL;
    }
    ret = PyString_FromStringAndSize(sigbuf, siglen);
    PyMem_Free(sigbuf);
    return ret;
}

/*
int dsa_verify_asn1(DSA *dsa, Blob *digest, Blob *sig) {
        return DSA_verify(0, digest->data, digest->len, sig->data, sig->len, dsa);
}
*/

int dsa_verify_asn1(DSA *dsa, PyObject *value, PyObject *sig) {
    const void *vbuf; 
    void *sbuf;
    int vlen, slen, ret;

#if PYTHON_API_VERSION >= 1009
    if ((PyObject_AsReadBuffer(value, &vbuf, &vlen) == -1)
        || (PyObject_AsReadBuffer(sig, (const void **)&sbuf, &slen) == -1))
        return -1;
#else /* assume PYTHON_API_VERSION == 1007 */
    if ((!PyString_Check(value)) 
        || (!PyString_Check(sig))) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return -1;
    }
    vlen = PyString_Size(value);
    vbuf = (const void *)PyString_AsString(value);
    slen = PyString_Size(sig);
    sbuf = (void *)PyString_AsString(sig);
#endif
    if ((ret = DSA_verify(0, vbuf, vlen, sbuf, slen, dsa)) == -1)
        PyErr_SetString(_dsa_err, ERR_reason_error_string(ERR_get_error()));
    return ret;
}

int dsa_check_key(DSA *dsa) {
    return (dsa->pub_key) && (dsa->priv_key);
}

int dsa_keylen(DSA *dsa) {
    return BN_num_bits(dsa->p);
}

int dsa_type_check(DSA *dsa) {
    return 1;
}
%}

