%{
#if PY_MAJOR_VERSION >= 3

/* Return the name of the file specified by p as a string object. */
PyObject* PyFile_Name(PyObject *pyfile) {
   return PyObject_GetAttrString(pyfile, "name");
}

FILE* PyFile_AsFile(PyObject *pyfile) {
    FILE* fp;
    int fd;
    const char *mode_str = NULL;

    if ((fd = PyObject_AsFileDescriptor(pyfile)) == -1) {
        PyErr_SetString(PyExc_BlockingIOError,
                        "Cannot find file handler for the Python file!");
        return NULL;
    }

    if (PyObject_HasAttrString(pyfile, "mode")) {
        PyObject *mode_obj = PyObject_GetAttrString(pyfile, "mode");
        if (mode_obj == NULL) {
             PyErr_SetString(PyExc_BlockingIOError,
                          "File does have NULL mode attribute!");
             return NULL;
        }

        /* convert to plain string
         * note that error checking is embedded in the function
         */
        mode_str = PyUnicode_AsUTF8AndSize(mode_obj, NULL);
    }
    else {
        mode_str = "rb";
        return NULL;
    }

    if((fp = fdopen(fd, mode_str)) == NULL) {
         PyErr_SetFromErrno(PyExc_IOError);
         return NULL;
    }

    return fp;
}

#else /* PY2K */

#define PyLong_FromLong(x) PyInt_FromLong(x)
#define PyUnicode_AsUTF8(x) PyString_AsString(x)

#endif /* PY_MAJOR_VERSION */
%}
