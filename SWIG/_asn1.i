/* Copyright (c) 2000 Ng Pheng Siong. All rights reserved.  */
/* $Id: _asn1.i,v 1.1 2003/06/22 17:30:52 ngps Exp $ */

%{
#include <openssl/asn1.h>
%}

%apply Pointer NONNULL { ASN1_INTEGER * };
%apply Pointer NONNULL { ASN1_UTCTIME * };
%apply Pointer NONNULL { BIO * };

%name(asn1_integer_get) extern long ASN1_INTEGER_get(ASN1_INTEGER *);
%name(asn1_utctime_print) extern int ASN1_UTCTIME_print(BIO *, ASN1_UTCTIME *);

%inline %{
/* nothing */
%}
