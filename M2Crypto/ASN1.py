"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: ASN1.py,v 1.1 2000/02/23 15:44:25 ngps Exp $'

import BIO
import M2Crypto
m2=M2Crypto

class ASN1_UTCTIME:
    def __init__(self, asn1):
        self.asn1 = asn1

    def __str__(self):
        buf = BIO.MemoryBuffer()
        m2.asn1_utctime_print(buf.bio_ptr(), self.asn1)
        return buf.read_all()


