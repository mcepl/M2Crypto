:orphan:

.. _howto-migration:

HOWTO: Migrating from M2Crypto to PyCA/cryptography
###################################################

Introduction
============

`PyCA/cryptography <https://github.com/pyca/cryptography>`__ is a
package which provides cryptographic recipes and primitives to Python
developers.

This document has instructions on how to migrate from M2Crypto to
PyCA/cryptography for features that are currently supported.

S/MIME
======

If your application does S/MIME signing, it can be migrated to
`PyCA/cryptography <https://github.com/pyca/cryptography>`__ by using
the ``PKCS7`` API, particularly the ``PKCS7SignatureBuilder`` class. Below
is an example migration showcasing the equivalent APIs and parameters in
`PyCA/cryptography <https://github.com/pyca/cryptography>`__.

M2Crypto:

.. testcode::

    from M2Crypto import BIO, SMIME
    s = SMIME.SMIME()
    s.load_key('../tests/signer_key.pem', '../tests/signer.pem')
    data = b'data'
    buf = BIO.MemoryBuffer(data)
    p7 = s.sign(buf, SMIME.PKCS7_DETACHED)

    out = BIO.MemoryBuffer()
    buf = BIO.MemoryBuffer(data)
    s.write(out, p7, buf)
    print(out.read())

.. testoutput::
   :hide:

   b'MIME-Version: 1.0\nContent-Type: multipart/signed;...


PyCA/cryptography:

.. testcode::

    from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs7, Encoding
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import load_pem_x509_certificate

    with open('../tests/signer_key.pem', 'rb') as key_data:
        key = load_pem_private_key(key_data.read(), password=None)
    with open('../tests/signer.pem', 'rb') as cert_data:
        cert = load_pem_x509_certificate(cert_data.read())

    output = pkcs7.PKCS7SignatureBuilder().set_data(
        b"data"
    ).add_signer(
        cert, key, hashes.SHA512(), rsa_padding=padding.PKCS1v15()
    ).sign(
        Encoding.SMIME, [pkcs7.PKCS7Options.DetachedSignature]
    )
    print(output)

.. testoutput::
   :hide:

   b'MIME-Version: 1.0\r\nContent-Type: multipart/signed;...
