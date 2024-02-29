:orphan:

.. _howto-migration:

HOWTO: Migrating from M2Crypto to PyCA/cryptography
###################################################

Introduction
************

`PyCA/cryptography <https://github.com/pyca/cryptography>`__ is a
package which provides cryptographic recipes and primitives to Python
developers.

This document has instructions on how to migrate from M2Crypto to
PyCA/cryptography for features that are currently supported.

S/MIME
******

Signing
=======

If your application does S/MIME signing, it can be migrated to
`PyCA/cryptography <https://github.com/pyca/cryptography>`__ by using
the ``PKCS7`` API, particularly the ``PKCS7SignatureBuilder`` class. Below
is an example migration showcasing the equivalent APIs and parameters in
`PyCA/cryptography <https://github.com/pyca/cryptography>`__.

M2Crypto
--------

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


PyCA/cryptography
-----------------

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


RSA
***

Following are migration examples for common operations with RSA key pairs.
The documentation for the relevant ``PyCA/cryptography`` APIs can be found
`here <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/>`__.

Signing and verifying
=====================

M2Crypto
--------

.. testcode::

    from M2Crypto import RSA
    import hashlib
    message = b"This is the message string"
    digest = hashlib.sha1(message).digest()
    key = RSA.load_key('../tests/rsa.priv.pem')
    signature = key.sign(digest, algo='sha1')

    assert key.verify(digest, signature, algo='sha1') == 1

    print(signature.hex())

.. testoutput::
   :hide:

   79aba937863cd5bfef254...

PyCA/cryptography
-----------------

.. testcode::

    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    with open('../tests/rsa.priv.pem', 'rb') as key_data:
        key = load_pem_private_key(key_data.read(), password=None)
    message = b"This is the message string"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    public_key = key.public_key()
    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())

    print(signature.hex())

.. testoutput::
   :hide:

   79aba937863cd5bfef254...


Encrypting and decrypting
=========================

M2Crypto
--------

.. testcode::

    from M2Crypto import RSA
    message = b"This is the message string"
    key = RSA.load_key('../tests/rsa.priv.pem')

    cipher_text = key.public_encrypt(message, RSA.pkcs1_padding)
    plain_text = key.private_decrypt(cipher_text, RSA.pkcs1_padding)

    assert plain_text == message


PyCA/cryptography
-----------------

.. testcode::

    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    with open('../tests/rsa.priv.pem', 'rb') as key_data:
        key = load_pem_private_key(key_data.read(), password=None)
    message = b"This is the message string"
    public_key = key.public_key()

    cipher_text = public_key.encrypt(message, padding.PKCS1v15())
    plain_text = key.decrypt(cipher_text, padding.PKCS1v15())

    assert plain_text == message


X.509 certificates
******************

Following are migration examples for common operations with X.509 certificates.
The documentation for the relevant ``PyCA/cryptography`` APIs can be found
`here <https://cryptography.io/en/latest/x509/>`__.

Loading and examining certificates
==================================

M2Crypto
--------

.. testcode::

    from M2Crypto import X509
    cert = X509.load_cert('../tests/x509.pem')
    print(cert.get_issuer())
    print(cert.get_subject())
    print(cert.get_not_before())
    print(cert.get_not_after())

.. testoutput::
   :hide:

   /C=US/ST=California/O=M2Crypto/CN=Heikki Toivonen
   /C=US/ST=California/O=M2Crypto/CN=X509
   Oct  7 15:12:02 2018 GMT
   Oct  4 15:12:02 2028 GMT


PyCA/cryptography
-----------------

.. testcode::

    from cryptography import x509
    with open('../tests/x509.pem', 'rb') as cert_data:
        cert = x509.load_pem_x509_certificate(cert_data.read())
    print(cert.issuer)
    print(cert.subject)
    print(cert.not_valid_before_utc)
    print(cert.not_valid_after_utc)


.. testoutput::
   :hide:

   <Name(C=US,ST=California,O=M2Crypto,CN=Heikki Toivonen)>
   <Name(C=US,ST=California,O=M2Crypto,CN=X509)>
   2018-10-07 15:12:02+00:00
   2028-10-04 15:12:02+00:00


Signature verification
==================================
Note that this example only checks that the signature of a certificate
matches a public key, as described in
`the OpenSSL documentation <https://www.openssl.org/docs/man3.2/man3/X509_verify.html>`__.
For complete X.509 path validation see
`PyCA/cryptography's X.509 verification module <https://cryptography.io/en/latest/x509/verification>`__.


M2Crypto
--------

.. testcode::

    from M2Crypto import X509
    cert = X509.load_cert('../tests/x509.pem')
    cacert = X509.load_cert("../tests/ca.pem")
    assert cert.verify(cacert.get_pubkey()) == 1


PyCA/cryptography
-----------------

.. testcode::

    from cryptography.x509 import load_pem_x509_certificate
    with open('../tests/ca.pem', 'rb') as cacert_data:
        cacert = load_pem_x509_certificate(cacert_data.read())
    with open('../tests/x509.pem', 'rb') as cert_data:
        cert = load_pem_x509_certificate(cert_data.read())
    cert.verify_directly_issued_by(cacert)

