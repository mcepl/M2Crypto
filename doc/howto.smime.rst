:orphan:

.. _howto-smime:

HOWTO: Programming S/MIME in Python with M2Crypto
=================================================

:author: Pheng Siong Ng <ngps@post1.com>
:copyright: © 2000, 2001 by Ng Pheng Siong.

Introduction
============

`M2Crypto <https://gitlab.com/m2crypto/m2crypto/>`__ is a
`Python <http://www.python.org>`__ interface to
`OpenSSL <http://www.openssl.org>`__. It makes available to the Python
programmer SSL functionality to implement clients and servers, S/MIME
v2, RSA, DSA, DH, symmetric ciphers, message digests and HMACs.

This document demonstrates programming S/MIME with M2Crypto.

S/MIME
======

S/MIME - Secure Multipurpose Internet Mail Extensions [RFC 2311, RFC
2312] - provides a consistent way to send and receive secure MIME data.
Based on the popular Internet MIME standard, S/MIME provides the
following cryptographic security services for electronic messaging
applications - *authentication*, *message integrity* and
*non-repudiation of origin* (using *digital signatures*), and *privacy*
and *data security* (using *encryption*).

Keys and Certificates
=====================

To create an S/MIME-signed message, you need an RSA key pair (this
consists of a public key and a private key) and an X.509 certificate of
said public key.

To create an S/MIME-encrypted message, you need an X.509 certificate for
each recipient.

To create an S/MIME-signed *and* -encrypted message, first create a
signed message, then encrypt the signed message with the recipients'
certificates.

You may generate key pairs and obtain certificates by using a commercial
*certification authority* service.

You can also do so using freely-available software. For many purposes,
e.g., automated S/MIME messaging by system administration processes,
this approach is cheap and effective.

We now work through using OpenSSL to generate key pairs and
certificates. This assumes you have OpenSSL installed properly on your
system.

First, we generate an X.509 certificate to be used for signing::

    openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out signer.pem

    Using configuration from /usr/local/pkg/openssl/openssl.cnf
    Generating a 1024 bit RSA private key
    ..++++++
    ....................++++++
    writing new private key to 'privkey.pem'
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:SG
    State or Province Name (full name) [Some-State]:.
    Locality Name (eg, city) []:.
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:M2Crypto
    Organizational Unit Name (eg, section) []:.
    Common Name (eg, YOUR name) []:S/MIME Sender
    Email Address []:sender@example.dom


This generates a 1024-bit RSA key pair, unencrypted, into
``privkey.pem``; it also generates a self-signed X.509 certificate for
the public key into ``signer.pem``. The certificate is valid for 365
days, i.e., a year.

Let's rename ``privkey.pem`` so that we know it is a companion of
``signer.pem``'s::

    mv privkey.pem signer_key.pem

To verify the content of ``signer.pem``, execute the following::

    openssl x509 -noout -text -in signer.pem

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 0 (0x0)
            Signature Algorithm: md5WithRSAEncryption
            Issuer: C=SG, O=M2Crypto, CN=S/MIME Sender/Email=sender@example.dom
            Validity
                Not Before: Mar 24 12:56:16 2001 GMT
                Not After : Mar 24 12:56:16 2002 GMT
            Subject: C=SG, O=M2Crypto, CN=S/MIME Sender/Email=sender@example.dom
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                RSA Public Key: (1024 bit)
                    Modulus (1024 bit):
                        00:a9:d6:e2:b5:11:3b:ae:3c:e2:17:31:70:e1:6e:
                        01:f4:19:6d:bd:2a:42:36:2b:37:34:e2:83:1d:0d:
                        11:2e:b4:99:44:db:10:67:be:97:5f:5b:1a:26:33:
                        46:23:2f:95:04:7a:35:da:9d:f9:26:88:39:9e:17:
                        cd:3e:eb:a8:19:8d:a8:2a:f1:43:da:55:a9:2e:2c:
                        65:ed:04:71:42:ce:73:53:b8:ea:7e:c7:f0:23:c6:
                        63:c5:5e:68:96:64:a7:b4:2a:94:26:76:eb:79:ea:
                        e3:4e:aa:82:09:4f:44:87:4a:12:62:b5:d7:1f:ca:
                        f2:ce:d5:ba:7e:1f:48:fd:b9
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Subject Key Identifier:
                    29:FB:38:B6:BF:E2:40:BB:FF:D5:71:D7:D5:C4:F0:83:1A:2B:C7:99
                X509v3 Authority Key Identifier:
                    keyid:29:FB:38:B6:BF:E2:40:BB:FF:D5:71:D7:D5:C4:F0:83:1A:2B:C7:99
                    DirName:/C=SG/O=M2Crypto/CN=S/MIME Sender/Email=sender@example.dom
                    serial:00

                X509v3 Basic Constraints:
                    CA:TRUE
        Signature Algorithm: md5WithRSAEncryption
            68:c8:6b:1b:fa:7c:9a:39:35:76:18:15:c9:fd:89:97:62:db:
            7a:b0:2d:13:dd:97:e8:1b:7a:9f:22:27:83:24:9d:2e:56:ec:
            97:89:3c:ef:16:55:80:5a:18:7c:22:d0:f6:bb:e3:a4:e8:59:
            30:ff:99:5a:93:3e:ea:bc:ee:7f:8d:d6:7d:37:8c:ac:3d:74:
            80:ce:7a:99:ba:27:b9:2a:a3:71:fa:a5:25:ba:47:17:df:07:
            56:96:36:fd:60:b9:6c:96:06:e8:e3:7b:9f:4b:6a:95:71:a8:
            34:fc:fc:b5:88:8b:c4:3f:1e:24:f6:52:47:b2:7d:44:67:d9:
            83:e8

Next, we generate a self-signed X.509 certificate for the recipient.
Note that ``privkey.pem`` will be recreated::

    openssl req -newkey rsa:1024 -nodes -x509 -days 365 -out recipient.pem

    Using configuration from /usr/local/pkg/openssl/openssl.cnf
    Generating a 1024 bit RSA private key
    .....................................++++++
    .................++++++
    writing new private key to 'privkey.pem'
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:SG
    State or Province Name (full name) [Some-State]:.
    Locality Name (eg, city) []:.
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:M2Crypto
    Organizational Unit Name (eg, section) []:.
    Common Name (eg, YOUR name) []:S/MIME Recipient
    Email Address []:recipient@example.dom

Again, rename ``privkey.pem``::

    mv privkey.pem recipient_key.pem


In the examples to follow, S/MIME Sender, ``<sender@example.dom>``,
shall be the sender of S/MIME messages, while S/MIME Recipient,
``<recipient@example.dom>``, shall be the recipient of S/MIME messages.

Armed with the key pairs and certificates, we are now ready to begin
programming S/MIME in Python.

    **Note:** The private keys generated above are *not
    passphrase-protected*, i.e., they are *in the clear*. Anyone who has
    access to such a key can generate S/MIME-signed messages with it,
    and decrypt S/MIME messages encrypted to it's corresponding public
    key.

    We may passphrase-protect the keys, if we so choose. M2Crypto will
    prompt the user for the passphrase when such a key is being loaded.

M2Crypto.SMIME
==============

The Python programmer accesses M2Crypto's S/MIME functionality through
class ``SMIME`` in the module ``M2Crypto.SMIME``. Typically, an
``SMIME`` object is instantiated; the object is then set up for the
intended operation: sign, encrypt, decrypt or verify; finally, the
operation is invoked on the object.

``M2Crypto.SMIME`` makes extensive use of ``M2Crypto.BIO``:
``M2Crypto.BIO`` is a Python abstraction of the ``BIO`` abstraction in
OpenSSL. A commonly used ``BIO`` abstraction in M2Crypto is
``M2Crypto.BIO.MemoryBuffer``, which implements a memory-based file-like
object, similar to Python's own ``StringIO``.

Sign
====

The following code demonstrates how to generate an S/MIME-signed
message. ``randpool.dat`` contains random data which is used to seed
OpenSSL's pseudo-random number generator via M2Crypto::

    from M2Crypto import BIO, Rand, SMIME

    def makebuf(text):
        return BIO.MemoryBuffer(text)

    # Make a MemoryBuffer of the message.
    buf = makebuf('a sign of our times')

    # Seed the PRNG.
    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object; set it up; sign the buffer.
    s = SMIME.SMIME()
    s.load_key('signer_key.pem', 'signer.pem')
    p7 = s.sign(buf, SMIME.PKCS7_DETACHED)


``p7`` now contains a *PKCS #7 signature blob* wrapped in an
``M2Crypto.SMIME.PKCS7`` object. Note that ``buf`` has been consumed by
``sign()`` and has to be recreated if it is to be used again.

We may now send the signed message via SMTP. In these examples, we shall
not do so; instead, we'll render the S/MIME output in mail-friendly
format, and pretend that our messages are sent and received
correctly::

    # Recreate buf.
    buf = makebuf('a sign of our times')

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    out.write('From: sender@example.dom\n')
    out.write('To: recipient@example.dom\n')
    out.write('Subject: M2Crypto S/MIME testing\n')
    s.write(out, p7, buf)

    print(out.read())

    # Save the PRNG's state.
    Rand.save_file('randpool.dat')

Here's the output::

    From: sender@example.dom
    To: recipient@example.dom
    Subject: M2Crypto S/MIME testing
    MIME-Version: 1.0
    Content-Type: multipart/signed ; protocol="application/x-pkcs7-signature" ; micalg=sha1 ; boundary="----3C93156FC7B4EBF49FE9C7DB7F503087"

    This is an S/MIME signed message

    ------3C93156FC7B4EBF49FE9C7DB7F503087
    a sign of our times
    ------3C93156FC7B4EBF49FE9C7DB7F503087
    Content-Type: application/x-pkcs7-signature; name="smime.p7s"
    Content-Transfer-Encoding: base64
    Content-Disposition: attachment; filename="smime.p7s"

    MIIE8AYJKoZIhvcNAQcCoIIE4TCCBN0CAQExCzAJBgUrDgMCGgUAMCIGCSqGSIb3
    DQEHAaAVBBNhIHNpZ24gb2Ygb3VyIHRpbWVzoIIC5zCCAuMwggJMoAMCAQICAQAw
    DQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRv
    MRYwFAYDVQQDEw1TL01JTUUgU2VuZGVyMSEwHwYJKoZIhvcNAQkBFhJzZW5kZXJA
    ZXhhbXBsZS5kb20wHhcNMDEwMzMxMTE0MDMzWhcNMDIwMzMxMTE0MDMzWjBbMQsw
    CQYDVQQGEwJTRzERMA8GA1UEChMITTJDcnlwdG8xFjAUBgNVBAMTDVMvTUlNRSBT
    ZW5kZXIxITAfBgkqhkiG9w0BCQEWEnNlbmRlckBleGFtcGxlLmRvbTCBnzANBgkq
    hkiG9w0BAQEFAAOBjQAwgYkCgYEA5c5Tj1CHTSOxa1q2q0FYiwMWYHptJpJcvtZm
    UwrgU5sHrA8OnCM0cDXEj0KPf3cfNjHffB8HWMzI4UEgNmFXQNsxoGZ+iqwxLlNj
    y9Mh7eFW/Bjq5hNXbouSlQ0rWBRkoxV64y+t6lQehb32WfYXQbKFxFJSXzSxOx3R
    8YhSPd0CAwEAAaOBtjCBszAdBgNVHQ4EFgQUXOyolL1t4jaBwZFRM7MS8nBLzUow
    gYMGA1UdIwR8MHqAFFzsqJS9beI2gcGRUTOzEvJwS81KoV+kXTBbMQswCQYDVQQG
    EwJTRzERMA8GA1UEChMITTJDcnlwdG8xFjAUBgNVBAMTDVMvTUlNRSBTZW5kZXIx
    ITAfBgkqhkiG9w0BCQEWEnNlbmRlckBleGFtcGxlLmRvbYIBADAMBgNVHRMEBTAD
    AQH/MA0GCSqGSIb3DQEBBAUAA4GBAHo3DrCHR86fSTVAvfiXdSswWqKtCEhUHRdC
    TLFGl4hDk2GyZxaFuqZwiURz/H7nMicymI2wkz8H/wyHFg8G3BIehURpj2v/ZWXY
    eovbgS7EZALVVkDj4hNl/IIHWd6Gtv1UODf7URbxtl3hQ9/eTWITrefT1heuPnar
    8czydsOLMYIBujCCAbYCAQEwYDBbMQswCQYDVQQGEwJTRzERMA8GA1UEChMITTJD
    cnlwdG8xFjAUBgNVBAMTDVMvTUlNRSBTZW5kZXIxITAfBgkqhkiG9w0BCQEWEnNl
    bmRlckBleGFtcGxlLmRvbQIBADAJBgUrDgMCGgUAoIGxMBgGCSqGSIb3DQEJAzEL
    BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTAxMDMzMTExNDUwMlowIwYJKoZI
    hvcNAQkEMRYEFOoeRUd8ExIYXfQq8BTFuKWrSP3iMFIGCSqGSIb3DQEJDzFFMEMw
    CgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMCAgFAMAcGBSsO
    AwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIGAQpU8hFUtLCF6hO2t
    ec9EYJ/Imqqiiw+BxWxkUUVT81Vbjwdn9JST6+sztM5JRP2ZW+b4txEjZriYC8f3
    kv95YMTGbIsuWkJ93GrbvqoJ/CxO23r9WWRnZEm/1EZN9ZmlrYqzBTxnNRmP3Dhj
    cW8kzZwH+2/2zz2G7x1HxRWH95A=

    ------3C93156FC7B4EBF49FE9C7DB7F503087--


Verify
======

Assume the above output has been saved into ``sign.p7``. Let's now
verify the signature::

    from M2Crypto import SMIME, X509

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load the signer's cert.
    x509 = X509.load_cert('signer.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Load the signer's CA cert. In this case, because the signer's
    # cert is self-signed, it is the signer's cert itself.
    st = X509.X509_Store()
    st.load_info('signer.pem')
    s.set_x509_store(st)

    # Load the data, verify it.
    p7, data = SMIME.smime_load_pkcs7('sign.p7')
    v = s.verify(p7, data)
    print(v)
    print(data)
    print(data.read())

Here's the output of the above program::

    a sign of our times
    <M2Crypto.BIO.BIO instance at 0x822012c>
    a sign of our times

Suppose, instead of loading ``signer.pem`` above, we load
``recipient.pem``. That is, we do a global substitution of
``recipient.pem`` for ``signer.pem`` in the above program. Here's the
modified program's output::

    Traceback (most recent call last):
      File "./verify.py", line 22, in ?
        v = s.verify(p7)
      File "/usr/local/home/ngps/prog/m2/M2Crypto/SMIME.py", line 205, in verify
        raise SMIME_Error, Err.get_error()
    M2Crypto.SMIME.SMIME_Error: 312:error:21075075:PKCS7 routines:PKCS7_verify:certificate verify error:pk7_smime.c:213:Verify error:self signed certificate


As displayed, the error is generated by line 213 of OpenSSL's
``pk7_smime.c`` (as of OpenSSL 0.9.6); if you are a C programmer, you
may wish to look up the C source to explore OpenSSL's S/MIME
implementation and understand why the error message is worded thus.

Encrypt
=======

We now demonstrate how to generate an S/MIME-encrypted message::

    from M2Crypto import BIO, Rand, SMIME, X509

    def makebuf(text):
        return BIO.MemoryBuffer(text)

    # Make a MemoryBuffer of the message.
    buf = makebuf('a sign of our times')

    # Seed the PRNG.
    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert('recipient.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(buf)

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    out.write('From: sender@example.dom\n')
    out.write('To: recipient@example.dom\n')
    out.write('Subject: M2Crypto S/MIME testing\n')
    s.write(out, p7)

    print(out.read())

    # Save the PRNG's state.
    Rand.save_file('randpool.dat')

Here's the output of the above program::

    From: sender@example.dom
    To: recipient@example.dom
    Subject: M2Crypto S/MIME testing
    MIME-Version: 1.0
    Content-Disposition: attachment; filename="smime.p7m"
    Content-Type: application/x-pkcs7-mime; name="smime.p7m"
    Content-Transfer-Encoding: base64

    MIIBVwYJKoZIhvcNAQcDoIIBSDCCAUQCAQAxggEAMIH9AgEAMGYwYTELMAkGA1UE
    BhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRkwFwYDVQQDExBTL01JTUUgUmVjaXBp
    ZW50MSQwIgYJKoZIhvcNAQkBFhVyZWNpcGllbnRAZXhhbXBsZS5kb20CAQAwDQYJ
    KoZIhvcNAQEBBQAEgYCBaXZ+qjpBEZwdP7gjfzfAtQitESyMwo3i+LBOw6sSDir6
    FlNDPCnkrTvqDX3Rt6X6vBtTCYOm+qiN7ujPkOU61cN7h8dvHR8YW9+0IPY80/W0
    lZ/HihSRgwTNd7LnxUUcPx8YV1id0dlmP0Hz+Lg+mHf6rqaR//JcYhX9vW4XvjA7
    BgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECMN+qya6ADywgBgHr9Jkhwn5Gsdu7BwX
    nIQfYTYcdL9I5Sk=


Decrypt
=======

Assume the above output has been saved into ``encrypt.p7``. Decrypt the
message thusly::

    from M2Crypto import BIO, SMIME, X509

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load private key and cert.
    s.load_key('recipient_key.pem', 'recipient.pem')

    # Load the encrypted data.
    p7, data = SMIME.smime_load_pkcs7('encrypt.p7')

    # Decrypt p7.
    out = s.decrypt(p7)

    print(out)

Here's the output::

    a sign of our times


Sign and Encrypt
================

Here's how to generate an S/MIME-signed/encrypted message::

    from M2Crypto import BIO, Rand, SMIME, X509

    def makebuf(text):
        return BIO.MemoryBuffer(text)

    # Make a MemoryBuffer of the message.
    buf = makebuf('a sign of our times')

    # Seed the PRNG.
    Rand.load_file('randpool.dat', -1)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load signer's key and cert. Sign the buffer.
    s.load_key('signer_key.pem', 'signer.pem')
    p7 = s.sign(buf)

    # Load target cert to encrypt the signed message to.
    x509 = X509.load_cert('recipient.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Create a temporary buffer.
    tmp = BIO.MemoryBuffer()

    # Write the signed message into the temporary buffer.
    s.write(tmp, p7)

    # Encrypt the temporary buffer.
    p7 = s.encrypt(tmp)

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    out.write('From: sender@example.dom\n')
    out.write('To: recipient@example.dom\n')
    out.write('Subject: M2Crypto S/MIME testing\n')
    s.write(out, p7)

    print(out.read())

    # Save the PRNG's state.
    Rand.save_file('randpool.dat')

Here's the output of the above program::

    From: sender@example.dom
    To: recipient@example.dom
    Subject: M2Crypto S/MIME testing
    MIME-Version: 1.0
    Content-Disposition: attachment; filename="smime.p7m"
    Content-Type: application/x-pkcs7-mime; name="smime.p7m"
    Content-Transfer-Encoding: base64

    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


Decrypt and Verify
==================

Suppose the above output has been saved into ``se.p7``. The following
demonstrates how to decrypt and verify it::

    from M2Crypto import BIO, SMIME, X509

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load private key and cert.
    s.load_key('recipient_key.pem', 'recipient.pem')

    # Load the signed/encrypted data.
    p7, data = SMIME.smime_load_pkcs7('se.p7')

    # After the above step, 'data' == None.
    # Decrypt p7. 'out' now contains a PKCS #7 signed blob.
    out = s.decrypt(p7)

    # Load the signer's cert.
    x509 = X509.load_cert('signer.pem')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Load the signer's CA cert. In this case, because the signer's
    # cert is self-signed, it is the signer's cert itself.
    st = X509.X509_Store()
    st.load_info('signer.pem')
    s.set_x509_store(st)

    # Recall 'out' contains a PKCS #7 blob.
    # Transform 'out'; verify the resulting PKCS #7 blob.
    p7_bio = BIO.MemoryBuffer(out)
    p7, data = SMIME.smime_load_pkcs7_bio(p7_bio)
    v = s.verify(p7)

    print(v)


The output is as follows::

    a sign of our times


Sending S/MIME messages via SMTP
================================

In the above examples, we've assumed that our S/MIME messages are sent
and received automagically. The following is a Python function that
generates S/MIME-signed/encrypted messages and sends them via
SMTP::

    from M2Crypto import BIO, SMIME, X509
    import smtplib, string, sys

    def sendsmime(from_addr, to_addrs, subject, msg, from_key, from_cert=None, to_certs=None, smtpd='localhost'):

        msg_bio = BIO.MemoryBuffer(msg)
        sign = from_key
        encrypt = to_certs

        s = SMIME.SMIME()
        if sign:
            s.load_key(from_key, from_cert)
            if encrypt:
                p7 = s.sign(msg_bio, flags=SMIME.PKCS7_TEXT)
            else:
                p7 = s.sign(msg_bio, flags=SMIME.PKCS7_TEXT|SMIME.PKCS7_DETACHED)
            msg_bio = BIO.MemoryBuffer(msg) # Recreate coz sign() has consumed it.

        if encrypt:
            sk = X509.X509_Stack()
            for x in to_certs:
                sk.push(X509.load_cert(x))
            s.set_x509_stack(sk)
            s.set_cipher(SMIME.Cipher('des_ede3_cbc'))
            tmp_bio = BIO.MemoryBuffer()
            if sign:
                s.write(tmp_bio, p7)
            else:
                tmp_bio.write(msg)
            p7 = s.encrypt(tmp_bio)

        out = BIO.MemoryBuffer()
        out.write('From: %s\r\n' % from_addr)
        out.write('To: %s\r\n' % string.join(to_addrs, ", "))
        out.write('Subject: %s\r\n' % subject)
        if encrypt:
            s.write(out, p7)
        else:
            if sign:
                s.write(out, p7, msg_bio, SMIME.PKCS7_TEXT)
            else:
                out.write('\r\n')
                out.write(msg)
        out.close()

        smtp = smtplib.SMTP()
        smtp.connect(smtpd)
        smtp.sendmail(from_addr, to_addrs, out.read())
        smtp.quit()


This function sends plain, S/MIME-signed, S/MIME-encrypted, and
S/MIME-signed/encrypted messages, depending on the parameters
``from_key`` and ``to_certs``. The function's output interoperates with
Netscape Messenger.

Verifying origin of S/MIME messages
===================================

In our examples above that decrypt or verify messages, we skipped a
step: verifying that the ``from`` address of the message matches the
``email address`` attribute in the sender's certificate.

The premise of current X.509 certification practice is that the CA is
supposed to verify your identity, and to issue a certificate with
``email address`` that matches your actual mail address. (Verisign's
March 2001 failure in identity verification resulting in Microsoft
certificates being issued to spoofers notwithstanding.)

If you run your own CA, your certification practice is up to you, of
course, and it would probably be part of your security policy.

Whether your S/MIME messaging application needs to verify the ``from``
addresses of S/MIME messages depends on your security policy and your
system's threat model, as always.

Interoperating with Netscape Messenger
======================================

Suppose S/MIME Recipient uses Netscape Messenger. To enable Messenger to
handle S/MIME messages from S/MIME Sender, S/MIME Recipient needs to
configure Messenger with his private key and certificate, as well as
S/MIME Sender's certificate.

    **Note:** Configuring Messenger's POP or IMAP settings so that it
    retrieves mail correctly is beyond the scope of this HOWTO.

The following steps demonstrate how to import S/MIME Recipient's private
key and certificate for Messenger:

1. Transform S/MIME Recipient's private key and certificate into *PKCS
   #12* format::

    openssl pkcs12 -export -in recipient.pem -inkey recipient_key.pem \
        -name "S/MIME Recipient" -out recipient.p12

    Enter Export Password:<enter>
    Verifying password - Enter Export Password:<enter>

2. Start Messenger.

3. Click on the (open) "lock" icon at the bottom left corner of
   Messenger's window. This brings up the "Security Info" dialog box.

4. Click on "Yours" under "Certificates".

5. Select "Import a certificate", then pick ``recipient.p12`` from the
   ensuing file selection dialog box.

Next, you need to import ``signer.pem`` as a CA certificate, so that
Messenger will mark messages signed by S/MIME Sender as "trusted":

1. Create a DER encoding of ``signer.pem``::

    openssl x509 -inform pem -outform der -in signer.pem -out signer.der

2. Install ``signer.der`` into Messenger as MIME type
   ``application/x-x509-ca-cert``. You do this by downloading
   ``signer.der`` via Navigator from a HTTP or HTTPS server, with the
   correct MIME type mapping. (You may use ``demo/ssl/https_srv.py``,
   bundled with M2Crypto, for this purpose.) Follow the series of dialog
   boxes to accept ``signer.der`` as a CA for certifying email users.

S/MIME Recipient is now able to decrypt and read S/MIME Sender's
messages with Messenger. Messenger will indicate that S/MIME Sender's
messages are signed, encrypted, or encrypted *and* signed, as the case
may be, via the "stamp" icon on the message window's top right corner.

Clicking on the "stamp" icon brings you to the Security Info dialog box.
Messenger informs you that the message is, say, encrypted with 168-bit
DES-EDE3-CBC and that it is digitally signed by the private key
corresponding to the public key contained in the certificate
``signer.pem``.

Interoperating with Microsoft Outlook
=====================================

I do not know how to do this, as I do not use Outlook. (Nor do I use
Netscape Messenger, actually. I use Mutt, top dog of MUAs. ;-)
Information on how to configure Outlook with keys and certificates so
that it handles S/MIME mail is gratefully accepted.

ZSmime
======

ZSmime is a `Zope <http://www.zope.org>`__ *product* that enables Zope
to generate S/MIME-signed/encrypted messages. ZSmime demonstrates how to
invoke M2Crypto in a web application server extension.

ZSmime has its own
`HOWTO <http://sandbox.rulemaker.net/ngps/zope/zsmime/howto.html>`__
explaining its usage. (That HOWTO has some overlap in content with this
document.)

Resources
=========

-  IETF S/MIME Working Group - http://www.imc.org/ietf-smime

-  S/MIME and OpenPGP - http://www.imc.org/smime-pgpmime.html

-  S/MIME Freeware Library -
   http://www.getronicsgov.com/hot/sfl_home.htm

-  Mozilla Network Security Services -
   http://www.mozilla.org/projects/security/pkg/nss

-  S/MIME Cracking Screen Saver - http://www.counterpane.com/smime.html
