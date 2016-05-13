/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.
 * Copyright (c) 2009-2010 Heikki Toivonen. All rights reserved.
*/
/* $Id: _rand.i 721 2010-02-13 06:30:33Z heikki $ */

%module _rand

%rename(rand_file_name) RAND_file_name;
extern const char *RAND_file_name(char *, size_t );
%rename(rand_load_file) RAND_load_file;
extern int RAND_load_file(const char *, long);
%rename(rand_save_file) RAND_write_file;
extern int RAND_write_file(const char *);
%rename(rand_poll) RAND_poll;
extern int RAND_poll(void);
%rename(rand_status) RAND_status;
extern int RAND_status(void);
%rename(rand_cleanup) RAND_cleanup;
extern void RAND_cleanup(void);

%inline %{
static PyObject *_rand_err;

void rand_init(PyObject *rand_err) {
    Py_INCREF(rand_err);
    _rand_err = rand_err;
}

PyObject *rand_seed(PyObject *seed) {
    const void *buf;
    int len;

    if (m2_PyObject_AsReadBufferInt(seed, &buf, &len) == -1)
        return NULL;

    RAND_seed(buf, len);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rand_add(PyObject *blob, double entropy) {
    const void *buf;
    int len;

    if (m2_PyObject_AsReadBufferInt(blob, &buf, &len) == -1)
        return NULL;

    RAND_add(buf, len, entropy);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rand_bytes(int n) {
    void *blob;
    PyObject *obj;
    
    if (!(blob = PyMem_Malloc(n))) {
        PyErr_SetString(PyExc_MemoryError, "rand_bytes");
        return NULL;
    }
    if (RAND_bytes(blob, n)) {
#if PY_MAJOR_VERSION >= 3
        obj = PyBytes_FromStringAndSize(blob, n);
#else
        obj = PyString_FromStringAndSize(blob, n);
#endif // PY_MAJOR_VERSION >= 3
        PyMem_Free(blob);
        return obj;
    } else {
        PyMem_Free(blob);
        Py_INCREF(Py_None);
        return Py_None;
    }
}

PyObject *rand_pseudo_bytes(int n) {
    int ret;
    unsigned char *blob;
    PyObject *tuple;
    
    if (!(blob=(unsigned char *)PyMem_Malloc(n))) {
        PyErr_SetString(PyExc_MemoryError, "rand_pseudo_bytes");
        return NULL;
    }
    if (!(tuple=PyTuple_New(2))) {
        PyErr_SetString(PyExc_RuntimeError, "PyTuple_New() fails");
        PyMem_Free(blob);
        return NULL;
    }
    ret = RAND_pseudo_bytes(blob, n);
    if (ret == -1) {
        PyMem_Free(blob);
        Py_DECREF(tuple);
        Py_INCREF(Py_None);
        return Py_None;
    } else {
#if PY_MAJOR_VERSION >= 3
        PyTuple_SET_ITEM(tuple, 0, PyBytes_FromStringAndSize((char*)blob, n));
#else
         PyTuple_SET_ITEM(tuple, 0, PyString_FromStringAndSize((char*)blob, n));
#endif // PY_MAJOR_VERSION >= 3

        PyMem_Free(blob);
        PyTuple_SET_ITEM(tuple, 1, PyInt_FromLong((long)ret));
        return tuple;
    }
}

PyObject *rand_file_name() {
    PyObject *obj;
    char *str;
    if ((obj = PyBytes_FromStringAndSize(NULL, BUFSIZ))==NULL) {
        PyErr_SetString(PyExc_MemoryError, "rand_file_name");
        return NULL;
    }
    str=PyBytes_AS_STRING(obj);
    if (RAND_file_name(str, BUFSIZ)==NULL) {
        PyErr_SetString(PyExc_RuntimeError, "rand_file_name");
        return NULL;
    }
    if (_PyBytes_Resize(&obj, (Py_ssize_t)strlen(str))!=0)
        return NULL; /* mem exception set by _PyBytes_Resize */
    return obj;
}

void rand_screen(void) {
#ifdef __WINDOWS__
    RAND_screen();
#endif
}

int rand_win32_event(unsigned int imsg, int wparam, long lparam) {
#ifdef __WINDOWS__
    return RAND_event(imsg, wparam, lparam);
#else
    return 0;
#endif
}
%}

/* 
2004-04-05, ngps: Still missing:
  RAND_egd
  RAND_egd_bytes
  RAND_query_egd_bytes
*/


