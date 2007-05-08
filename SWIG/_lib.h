/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif

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

void gen_callback(int p, int n, void *arg);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);

