/* Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/x509v3.h>
%}

%inline %{
static PyObject *_util_err;

void util_init(PyObject *util_err) {
    Py_INCREF(util_err);
    _util_err = util_err;
}
    
PyObject *util_hex_to_string(PyObject *blob) {
    PyObject *obj;
    const void *buf;
    char *ret;
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
    buf = (const void *)PyString_AsString(blob);
#endif
    ret = hex_to_string((unsigned char *)buf, (long)len);
    if (!ret) {
        PyErr_SetString(_util_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    obj = PyString_FromString(ret);
    OPENSSL_free(ret);
    return obj;
}

PyObject *util_string_to_hex(PyObject *blob) {
    PyObject *obj;
    const void *buf;
    unsigned char *ret;
    int len;

#if PYTHON_API_VERSION >= 1009
    if (PyObject_AsReadBuffer(blob, &buf, &len) == -1)
        return NULL;
#else /* assume PYTHON_API_VERSION == 1007 */
    if (!PyString_Check(blob)) {
        PyErr_SetString(PyExc_TypeError, "expected a string object");
        return NULL;
    }
    buf = (const void *)PyString_AsString(blob);
#endif
    ret = string_to_hex((char *)buf, (long *)&len);
    if (ret == NULL) {
        PyErr_SetString(_util_err, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }
    obj = PyString_FromStringAndSize(ret, len);
    OPENSSL_free(ret);
    return obj;
}
%}
