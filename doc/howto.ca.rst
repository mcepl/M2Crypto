:orphan:

.. _howto-ca:

HOWTO: Creating your own CA with OpenSSL
########################################

:author: Pheng Siong Ng <ngps@post1.com>
:copyright: © 2000, 2001 by Ng Pheng Siong.

Introduction
============

This is a HOWTO on creating your own *certification authority* (*CA*)
with OpenSSL.

I last created a CA about a year ago, when I began work on
`M2Crypto <https://gitlab.com/m2crypto/m2crypto/>`__ and needed
certificates for the SSL bits. I accepted the tools' default
settings then, e.g., certificate validity of 365 days; this meant
that my certificates, including my CA's certificate, have now
expired.

Since I am using these certificates for M2Crypto's demonstration
programs (and I have forgotten the passphrase to the CA's private
key), I decided to discard the old CA and start afresh. I also
decided to document the process, hence this HOWTO.

The Procedure
=============

I use ``CA.pl``, a Perl program written by Steve Hanson and bundled with
OpenSSL.

The following are the steps to create a CA:

1. Choose a directory to do your CA work. All commands are executed
   within this directory. Let's call the directory ``demo``.

2. Copy ``CA.pl`` and ``openssl.cnf`` into ``demo``.

3. Apply the following patch to ``CA.pl``, which allows it to generate a
   CA certificate with a validity period of 1095 days, i.e.,
   3 years::

    --- CA.pl.org   Sat Mar 31 12:40:13 2001
    +++ CA.pl       Sat Mar 31 12:41:15 2001
    @@ -97,7 +97,7 @@
                    } else {
                        print "Making CA certificate ...\n";
                        system ("$REQ -new -x509 -keyout " .
    -                       "${CATOP}/private/$CAKEY -out ${CATOP}/$CACERT $DAYS");
    +                       "${CATOP}/private/$CAKEY -out ${CATOP}/$CACERT -days 1095");
                        $RET=$?;
                    }
                }
           

4. Create a new CA like this::

    ./CA.pl -newca

    A certificate filename (or enter to create) <enter>

    Making CA certificate ...
    Using configuration from openssl.cnf
    Generating a 1024 bit RSA private key
    ............++++++
    ......................++++++
    writing new private key to './demoCA/private/cakey.pem'
    Enter PEM pass phrase: <secret passphrase here>
    Verifying password - Enter PEM pass phrase: <secret passphrase again>
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
    Locality Name (eg, city) []:..
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:DemoCA
    Organizational Unit Name (eg, section) []:.
    Common Name (eg, YOUR name) []:DemoCA Certificate Master
    Email Address []:certmaster@democa.dom

   This creates a new CA in the directory ``demoCA``. The CA's
   self-signed certificate is in ``demoCA/cacert.pem`` and its RSA key
   pair is in ``demoCA/private/cakey.pem``.

   ``demoCA/private/cakey.pem`` looks like this::

    cat demoCA/private/cakey.pem

    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: DES-EDE3-CBC,19973A9DBBB601BA

    eOq9WFScNiI4/UWEUaSnGTKpJv2JYuMD3HwQox2Q3Cd4zGqVjJ6gF3exa5126cKf
    X/bMVnwbPpuFZPiAIvaLyCjT6pYeXTBbSzs7/GQnvEOv+nYnDUFWi0Qm92qLk0uy
    pFi/M1aWheN3vir2ZlAw+DW0bOOZhj8tC7Co7lMYb0YE271b6/YRPZCwQ3GXAHUJ
    +aMYxlUDrK45aCUa/1CZDzTgk7h9cDgx2QJSIvYMYytCfI3zsuZMJS8/4OXLL0bI
    lKmAc1dwB3DqGJt5XK4WJesiNfdxeCNEgAcYtEAgYZTPIApU+kTgTCIxJl2nMW7j
    ax+Q1z7g+4MpgG20WD633D4z4dTlDdz+dnLi0rvuvxiwt+dUhrqiML1tyi+Z6EBH
    jU4/cLBWev3rYfrlp4x8J9mDte0YKOk3t0wQOHqRetTsIfdtjnFp/Hu3qDmTCWjD
    z/g7PPoO/bg/B877J9WBPbL/1hXXFYo88M+2aGlPOgDcFdiOqbLb2DCscohMbbVr
    A4mgiy2kwWfIE73qiyV7yyG8FlRvr1iib+jbT3LTGf743utYAAs7HNGuOUObhoyt
    jYvBD7ACn35P5YX7KTqvqErwdijxYCaNBCnvmRtmYSaNw9Kv1UJTxc5Vx7YLwIPk
    E9KyBgKI7vPOjWBZ27+zOvNycmv1ciNtpALAw4bWtXnhCDVTHaVDy34OkheMzNCg
    2cjcBFzOkMIjcI03KbTQXOFIQGlsTWXGzkNf/zBQ+KksT1MCj+zBXSCvlDASMckg
    kef21pGgUqPF14gKGfWX3sV4bjc1vbrRwq6zlG3nMuYqR5MtJJY9eQ==
    -----END RSA PRIVATE KEY-----


5. Next, generate a certificate request::

    ./CA.pl -newreq

    Using configuration from openssl.cnf
    Generating a 1024 bit RSA private key
    ..........++++++
    ..............++++++
    writing new private key to 'newreq.pem'
    Enter PEM pass phrase: <another secret passphrase here>
    Verifying password - Enter PEM pass phrase: <another secret passphrase again>
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:SG
    State or Province Name (full name) [Some-State]:..
    Locality Name (eg, city) []:.
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:M2Crypto
    Organizational Unit Name (eg, section) []:.
    Common Name (eg, YOUR name) []:localhost
    Email Address []:admin@server.example.dom

    Please enter the following 'extra' attributes
    to be sent with your certificate request
    A challenge password []:<enter>
    An optional company name []:<enter>
    Request (and private key) is in newreq.pem
           
\ 

    The certificate request and private key in ``newreq.pem`` looks like
    this::

        cat newreq.pem

        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,41B2874DF3D02DD4

        mg611EoVkLEooSTv+qTM0Ddmm/M1jE/Jy5RD/sc3LSMhuGu9xc26OgsTJmkQuIAh
        J/B4lAw8G59VTG6DykeEtrG0rUBx4bggc7PKbFuiN423YjJODWcHvVgnPOzXMQt+
        lY4tPl5+217MRHyx2NsWGrpkQNdu3GeSPOVMl3jeQiaXupONbwQ7rj42+X/VtAJP
        W4D1NNwu8aGCPyShsEXHc/fI1WDpphYWke97pOjIZVQESFZOPty5HjIYZux4U+td
        W81xODtq2ecJXc8fn2Wpa9y5VD1LT7oJksOuL1+Z04OVaeUe4x0swM17HlBm2kVt
        fe/C/L6kN27MwZhE331VjtTjSGl4/gknqQDbLOtqT06f3OISsDJETm2itllyhgzv
        C6Fi3N03rGFmKectijC+tws5k+P+HRG6sai33usk8xPokJqA+HYSWPz1XVlpRmv4
        kdjQOdST7ovU62mOTgf3ARcduPPwuzTfxOlYONe5NioO1APVHBrInQwcpLkpOTQR
        vI4roIN+b75/nihUWGUJn/nbbBa2Yl0N5Gs1Tyiy9Z+CcRT2TfWKBBFlEUIFl7Mb
        J9fTV3DI+k+akbR4il1NkQ8EcSmCr3WpA0I9n0EHI7ZVpVaHxc0sqaPFl8YGdFHq
        1Qk53C/w6+qPpDzT3yKFmG2LZytAAM1czvb6RbNRJJP2ZrpBwn/h99sUTo/yPfxY
        nueYmFJDm0uVNtG0icXGNUfSfnjKNTtHPAgyKGetRIC3kgJz/bo2w7EI6iEjBAzK
        l5TRm4x6ZJxwuXXMiJCehMMd8TC8ybwWO4AO19B3ebFFeTVsUgxSGA==
        -----END RSA PRIVATE KEY-----
        -----BEGIN CERTIFICATE REQUEST-----
        MIIBnTCCAQYCAQAwXTELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIw
        EAYDVQQDEwlsb2NhbGhvc3QxJzAlBgkqhkiG9w0BCQEWGGFkbWluQHNlcnZlci5l
        eGFtcGxlLmRvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr1nYY1Qrll1r
        uB/FqlCRrr5nvupdIN+3wF7q915tvEQoc74bnu6b8IbbGRMhzdzmvQ4SzFfVEAuM
        MuTHeybPq5th7YDrTNizKKxOBnqE2KYuX9X22A1Kh49soJJFg6kPb9MUgiZBiMlv
        tb7K3CHfgw5WagWnLl8Lb+ccvKZZl+8CAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4GB
        AHpoRp5YS55CZpy+wdigQEwjL/wSluvo+WjtpvP0YoBMJu4VMKeZi405R7o8oEwi
        PdlrrliKNknFmHKIaCKTLRcU59ScA6ADEIWUzqmUzP5Cs6jrSRo3NKfg1bd09D1K
        9rsQkRc9Urv9mRBIsredGnYECNeRaK5R1yzpOowninXC
        -----END CERTIFICATE REQUEST-----
           
\ 

    Decoding the certificate request gives the following::

        openssl req -text -noout < newreq.pem

        Using configuration from /usr/local/pkg/openssl/openssl.cnf
        Certificate Request:
           Data:
               Version: 0 (0x0)
               Subject: C=SG, O=M2Crypto, CN=localhost/Email=admin@server.example.dom
               Subject Public Key Info:
                   Public Key Algorithm: rsaEncryption
                   RSA Public Key: (1024 bit)
                       Modulus (1024 bit):
                           00:af:59:d8:63:54:2b:96:5d:6b:b8:1f:c5:aa:50:
                           91:ae:be:67:be:ea:5d:20:df:b7:c0:5e:ea:f7:5e:
                           6d:bc:44:28:73:be:1b:9e:ee:9b:f0:86:db:19:13:
                           21:cd:dc:e6:bd:0e:12:cc:57:d5:10:0b:8c:32:e4:
                           c7:7b:26:cf:ab:9b:61:ed:80:eb:4c:d8:b3:28:ac:
                           4e:06:7a:84:d8:a6:2e:5f:d5:f6:d8:0d:4a:87:8f:
                           6c:a0:92:45:83:a9:0f:6f:d3:14:82:26:41:88:c9:
                           6f:b5:be:ca:dc:21:df:83:0e:56:6a:05:a7:2e:5f:
                           0b:6f:e7:1c:bc:a6:59:97:ef
                       Exponent: 65537 (0x10001)
               Attributes:
                   a0:00
           Signature Algorithm: md5WithRSAEncryption
               7a:68:46:9e:58:4b:9e:42:66:9c:be:c1:d8:a0:40:4c:23:2f:
               fc:12:96:eb:e8:f9:68:ed:a6:f3:f4:62:80:4c:26:ee:15:30:
               a7:99:8b:8d:39:47:ba:3c:a0:4c:22:3d:d9:6b:ae:58:8a:36:
               49:c5:98:72:88:68:22:93:2d:17:14:e7:d4:9c:03:a0:03:10:
               85:94:ce:a9:94:cc:fe:42:b3:a8:eb:49:1a:37:34:a7:e0:d5:
               b7:74:f4:3d:4a:f6:bb:10:91:17:3d:52:bb:fd:99:10:48:b2:
               b7:9d:1a:76:04:08:d7:91:68:ae:51:d7:2c:e9:3a:8c:27:8a:
               75:c2

6. Now, sign the certificate request::

    ./CA.pl -sign

    Using configuration from openssl.cnf
    Enter PEM pass phrase: <CA's passphrase>
    Check that the request matches the signature
    Signature ok
    The Subjects Distinguished Name is as follows
    countryName           :PRINTABLE:'SG'
    organizationName      :PRINTABLE:'M2Crypto'
    commonName            :PRINTABLE:'localhost'
    emailAddress          :IA5STRING:'admin@server.example.dom'
    Certificate is to be certified until Mar 31 02:57:30 2002 GMT (365 days)
    Sign the certificate? [y/n]:y


    1 out of 1 certificate requests certified, commit?  [y/n]y
    Write out database with 1 new entries
    Data Base Updated
    Signed certificate is in newcert.pem
       
\ 

    ``newcert.pem`` looks like this::

        cat newcert.pem

        Certificate:
        Data:
           Version: 3 (0x2)
           Serial Number: 1 (0x1)
           Signature Algorithm: md5WithRSAEncryption
           Issuer: C=SG, O=DemoCA, CN=DemoCA Certificate Master/Email=certmaster@democa.dom
           Validity
               Not Before: Mar 31 02:57:30 2001 GMT
               Not After : Mar 31 02:57:30 2002 GMT
           Subject: C=SG, O=M2Crypto, CN=localhost/Email=admin@server.example.dom
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
               RSA Public Key: (1024 bit)
                   Modulus (1024 bit):
                       00:af:59:d8:63:54:2b:96:5d:6b:b8:1f:c5:aa:50:
                       91:ae:be:67:be:ea:5d:20:df:b7:c0:5e:ea:f7:5e:
                       6d:bc:44:28:73:be:1b:9e:ee:9b:f0:86:db:19:13:
                       21:cd:dc:e6:bd:0e:12:cc:57:d5:10:0b:8c:32:e4:
                       c7:7b:26:cf:ab:9b:61:ed:80:eb:4c:d8:b3:28:ac:
                       4e:06:7a:84:d8:a6:2e:5f:d5:f6:d8:0d:4a:87:8f:
                       6c:a0:92:45:83:a9:0f:6f:d3:14:82:26:41:88:c9:
                       6f:b5:be:ca:dc:21:df:83:0e:56:6a:05:a7:2e:5f:
                       0b:6f:e7:1c:bc:a6:59:97:ef
                   Exponent: 65537 (0x10001)
           X509v3 extensions:
               X509v3 Basic Constraints: 
        Certificate:
        Data:
           Version: 3 (0x2)
           Serial Number: 1 (0x1)
           Signature Algorithm: md5WithRSAEncryption
           Issuer: C=SG, O=DemoCA, CN=DemoCA Certificate Master/Email=certmaster@democa.dom
           Validity
               Not Before: Mar 31 02:57:30 2001 GMT
               Not After : Mar 31 02:57:30 2002 GMT
           Subject: C=SG, O=M2Crypto, CN=localhost/Email=admin@server.example.dom
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
               RSA Public Key: (1024 bit)
                   Modulus (1024 bit):
                       00:af:59:d8:63:54:2b:96:5d:6b:b8:1f:c5:aa:50:
                       91:ae:be:67:be:ea:5d:20:df:b7:c0:5e:ea:f7:5e:
                       6d:bc:44:28:73:be:1b:9e:ee:9b:f0:86:db:19:13:
                       21:cd:dc:e6:bd:0e:12:cc:57:d5:10:0b:8c:32:e4:
                       c7:7b:26:cf:ab:9b:61:ed:80:eb:4c:d8:b3:28:ac:
                       4e:06:7a:84:d8:a6:2e:5f:d5:f6:d8:0d:4a:87:8f:
                       6c:a0:92:45:83:a9:0f:6f:d3:14:82:26:41:88:c9:
                       6f:b5:be:ca:dc:21:df:83:0e:56:6a:05:a7:2e:5f:
                       0b:6f:e7:1c:bc:a6:59:97:ef
                   Exponent: 65537 (0x10001)
           X509v3 extensions:
               X509v3 Basic Constraints: 
                   CA:FALSE
               Netscape Comment: 
                   OpenSSL Generated Certificate
               X509v3 Subject Key Identifier: 
                   B3:D6:89:88:2F:B1:15:40:EC:0A:C0:30:35:3A:B7:DA:72:73:1B:4D
               X509v3 Authority Key Identifier: 
                   keyid:F9:6A:A6:34:97:6B:BC:BB:5A:17:0D:19:FC:62:21:0B:00:B5:0E:29
                   DirName:/C=SG/O=DemoCA/CN=DemoCA Certificate Master/Email=certmaster@democa.dom
                   serial:00

        Signature Algorithm: md5WithRSAEncryption
           
7. In certain situations, e.g., where your certificate and private key
   are to be used in an unattended SSL server, you may wish to not
   encrypt the private key, i.e., leave the key in the clear. This
   decision should be governed by your site's security policy and threat
   model, of course::

           openssl rsa < newkey.pem > newkey2.pem
           
           read RSA key
           Enter PEM pass phrase:<secret passphrase here>
           writing RSA key
           
   ``newkey2.pem`` looks like this::

        cat newkey2.pem

        -----BEGIN RSA PRIVATE KEY-----
        MIICXgIBAAKBgQCvWdhjVCuWXWu4H8WqUJGuvme+6l0g37fAXur3Xm28RChzvhue
        7pvwhtsZEyHN3Oa9DhLMV9UQC4wy5Md7Js+rm2HtgOtM2LMorE4GeoTYpi5f1fbY
        DUqHj2ygkkWDqQ9v0xSCJkGIyW+1vsrcId+DDlZqBacuXwtv5xy8plmX7wIDAQAB
        AoGAbAkU8w3W1Qu15Hle1bJSL7GMReoreqeblOBmMAZz4by0l6sXZXJpjWXo86f/
        +dASMYTMPC4ZTYtv06N07AFbjL+kDfqDMTfzQkYMHp1LAq1Ihbq1rHWSBH5n3ekq
        KiY8JKpv8DR5Po1iKaXJFuDByGDENJwYbSRSpSK3P+vkWWECQQDkEUE/ZPqqqZkQ
        2iWRPAsCbEID8SAraQl3DdCLYs/GgARfmmj4yUHEwkys9Jo1H8k4BdxugmaUwNi5
        YQ/CVzrXAkEAxNO80ArbGxPUmr11GHG/bGBYj1DUBkHZSc7dgxZdtUCLGNxQnNsg
        Iwq3n6j1sUzS3UW6abQ8bivYNOUcMKJAqQJBANQxFaLU4b/NQaODQ3aoBZpAfP9L
        5eFdvbet+7zjt2r5CpikgkwOfAmDuXEltx/8LevY0CllW+nErx9zJgVrwUsCQQCu
        76H5JiznPBDSF2FjgHWqVVdgyW4owY3mU739LHvNBLicN/RN9VPy0Suy8/CqzKT9
        lWPBXzf2k3FuUdNkRlFBAkEAmpXoybuiFR2S5Bma/ax96lVs0/VihhfC1zZP/X/F
        Br77+h9dIul+2DnyOl50zu0Sdzst1/7ay4JSDHyiBCMGSQ==
        -----END RSA PRIVATE KEY-----


That's it! The certificate, ``newcert.pem``, and the private key -
``newkey.pem`` (encrypted) or ``newkey2.pem`` (unencrypted) - are now
ready to be used. You may wish to rename the files to more intuitive
names.

You should also keep the CA's certificate ``demo/cacert.pem`` handy
for use when developing and deploying SSL or S/MIME applications.

Conclusion
==========

We've walked through the basic steps in the creation of a CA and
certificates using the tools that come with OpenSSL. We did not cover
more advanced topics such as constraining a certificate to be SSL-only
or S/MIME-only.

There exist several HOWTOs similar to this one on the net. This one is
written specifically to facilitate discussions in my other HOWTOs on
developing SSL and S/MIME applications in
`Python <http://www.python.org>`__ using
`M2Crypto <https://gitlab.com/m2crypto/m2crypto/>`__.

