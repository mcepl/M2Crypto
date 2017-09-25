%{
#if PY_MAJOR_VERSION >= 3


#else /* PY2K */

#define PyLong_FromLong(x) PyInt_FromLong(x)
#define PyUnicode_AsUTF8(x) PyString_AsString(x)

#endif /* PY_MAJOR_VERSION */
%}
