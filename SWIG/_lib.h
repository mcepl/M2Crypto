/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id: _lib.h,v 1.1 2003/06/22 17:30:52 ngps Exp $ */

typedef struct _blob {
	unsigned char *data;
	int len;
} Blob;

Blob *blob_new(int len, const char *errmsg);
Blob *blob_copy(Blob *from, const char *errmsg);
void blob_free(Blob *blob);

void gen_callback(int p, int n, void *arg);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);

