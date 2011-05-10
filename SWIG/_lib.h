/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

#if PY_VERSION_HEX < 0x02060000
struct Py_buffer /* Only a subset */
{
  void *buf;
  Py_ssize_t len;
};

#define PyBUF_CONTIG_RO 0
#endif /* PY_VERSION_HEX < 0x02060000 */

typedef struct _blob {
	unsigned char *data;
	int len;
} Blob;

Blob *blob_new(int len, const char *errmsg);
Blob *blob_copy(Blob *from, const char *errmsg);
void blob_free(Blob *blob);

static int m2_PyObject_AsReadBufferInt(PyObject *obj, const void **buffer,
                                       int *buffer_len);
static int m2_PyString_AsStringAndSizeInt(PyObject *obj, char **s, int *len);

/* Always use these two together, to correctly handle non-memoryview objects. */
static int m2_PyObject_GetBufferInt(PyObject *obj, Py_buffer *view, int flags);
static void m2_PyBuffer_Release(PyObject *obj, Py_buffer *view);

void gen_callback(int p, int n, void *arg);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);

