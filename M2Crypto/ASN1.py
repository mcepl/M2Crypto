"""Copyright (c) 1999-2003 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: ASN1.py,v 1.2 2002/12/23 03:52:12 ngps Exp $'

import BIO
import m2

class ASN1_UTCTIME:
    def __init__(self, asn1):
        self.asn1 = asn1

    def __str__(self):
        buf = BIO.MemoryBuffer()
        m2.asn1_utctime_print(buf.bio_ptr(), self.asn1)
        return buf.read_all()


