#!/usr/bin/env python

"""S/MIME HOWTO demo program.

Copyright (c) 1999-2001 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: decrypt.py,v 1.1 2001/04/02 13:06:57 ngps Exp $'

from M2Crypto import BIO, SMIME, X509

# Instantiate an SMIME object.
s = SMIME.SMIME()

# Load private key and cert.
s.load_key('recipient_key.pem', 'recipient.pem')

# Load the encrypted data.
p7, data = SMIME.smime_load_pkcs7('encrypt.p7')

# Decrypt p7.
out = s.decrypt(p7)
    
print out

