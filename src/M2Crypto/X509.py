
"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

import binascii
import logging

from M2Crypto import ASN1, BIO, EVP, m2  # noqa
from typing import List, Optional, Union  # noqa

FORMAT_DER = 0
FORMAT_PEM = 1

__g = globals()
for x in dir(m2):
    if x.startswith('VERIFY_'):
        __g[x.lower()] = getattr(m2, x)

log = logging.getLogger(__name__)


class X509Error(ValueError):
    pass


m2.x509_init(X509Error)

V_OK: int = m2.X509_V_OK


class X509_Extension(object):
    """
    X509 Extension
    """

    m2_x509_extension_free = m2.x509_extension_free

    def __init__(
        self, x509_ext_ptr: Optional[bytes] = None, _pyfree: int = 1
    ) -> None:
        self.x509_ext = x509_ext_ptr
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0) and self.x509_ext:
            self.m2_x509_extension_free(self.x509_ext)

    def _ptr(self) -> bytes:
        return self.x509_ext

    def set_critical(self, critical: int = 1) -> int:
        """
        Mark this extension critical or noncritical. By default an
        extension is not critical.

        :param critical: Nonzero sets this extension as critical.
                         Calling this method without arguments will
                         set this extension to critical.
        :return: 1 for success, 0 for failure
        """
        return m2.x509_extension_set_critical(self.x509_ext, critical)

    def get_critical(self) -> int:
        """
        Return whether or not this is a critical extension.

        :return:  Nonzero if this is a critical extension.
        """
        return m2.x509_extension_get_critical(self.x509_ext)

    def get_name(self) -> str:
        """
        Get the extension name, for example 'subjectAltName'.
        """
        out = m2.x509_extension_get_name(self.x509_ext)
        return out.decode() if isinstance(out, bytes) else out

    def get_value(self, flag: int = 0, indent: int = 0) -> str:
        """
        Get the extension value, for example 'DNS:www.example.com'.

        :param flag:   Flag to control what and how to print.
        :param indent: How many spaces to print before actual value.
        """
        buf = BIO.MemoryBuffer()
        m2.x509_ext_print(buf.bio_ptr(), self.x509_ext, flag, indent)
        out = buf.read_all()
        return out.decode() if isinstance(out, bytes) else out


def new_extension(
    name: str, value: bytes, critical: int = 0, _pyfree: int = 1
) -> X509_Extension:
    """
    Create new X509_Extension instance.
    """
    if (
        name == 'subjectKeyIdentifier'
        and value.strip('0123456789abcdefABCDEF:') != ''
    ):
        raise ValueError('value must be precomputed hash')
    ctx = m2.x509v3_set_nconf()
    x509_ext_ptr = m2.x509v3_ext_conf(None, ctx, name, value)
    if x509_ext_ptr is None:
        raise X509Error(
            "Cannot create X509_Extension with name '%s' and value '%s'"
            % (name, value)
        )
    x509_ext = X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext


class X509_Extension_Stack(object):
    """
    X509 Extension Stack

    :warning: Do not modify the underlying OpenSSL stack
              except through this interface, or use any OpenSSL
              functions that do so indirectly. Doing so will get the
              OpenSSL stack and the internal pystack of this class out
              of sync, leading to python memory leaks, exceptions or
              even python crashes!
    """

    m2_sk_x509_extension_free = m2.sk_x509_extension_free

    def __init__(
        self, stack: Optional[bytes] = None, _pyfree: int = 0
    ) -> None:
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            num = m2.sk_x509_extension_num(self.stack)
            for i in range(num):
                self.pystack.append(
                    X509_Extension(
                        m2.sk_x509_extension_value(self.stack, i),
                        _pyfree=_pyfree,
                    )
                )
        else:
            self.stack = m2.sk_x509_extension_new_null()
            self._pyfree = 1
            self.pystack = (
                []
            )  # This must be kept in sync with self.stack

    def __del__(self) -> None:
        # see BIO.py - unbalanced __init__ / __del__
        if getattr(self, '_pyfree', 0):
            self.m2_sk_x509_extension_free(self.stack)

    def __len__(self) -> int:
        assert m2.sk_x509_extension_num(self.stack) == len(
            self.pystack
        )
        return len(self.pystack)

    def __getitem__(self, idx: int) -> X509_Extension:
        return self.pystack[idx]

    def __iter__(self):
        return iter(self.pystack)

    def _ptr(self) -> bytes:
        return self.stack

    def push(self, x509_ext: X509_Extension) -> int:
        """
        Push X509_Extension object onto the stack.

        :param x509_ext: X509_Extension object to be pushed onto the stack.
        :return: The number of extensions on the stack.
        """
        self.pystack.append(x509_ext)
        ret = m2.sk_x509_extension_push(self.stack, x509_ext._ptr())
        assert ret == len(self.pystack)
        return ret

    def pop(self) -> X509_Extension:
        """
        Pop X509_Extension object from the stack.

        :return: X509_Extension popped
        """
        x509_ext_ptr = m2.sk_x509_extension_pop(self.stack)
        if x509_ext_ptr is None:
            assert len(self.pystack) == 0
            return None
        return self.pystack.pop()


class X509_Name_Entry(object):
    """
    X509 Name Entry
    """

    m2_x509_name_entry_free = m2.x509_name_entry_free

    def __init__(
        self, x509_name_entry: bytes, _pyfree: int = 0
    ) -> None:
        """
        :param x509_name_entry: this should be OpenSSL X509_NAME_ENTRY binary
        :param _pyfree:
        """
        self.x509_name_entry = x509_name_entry
        self._pyfree = _pyfree

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_name_entry_free(self.x509_name_entry)

    def _ptr(self) -> bytes:
        return self.x509_name_entry

    def set_object(self, asn1obj: ASN1.ASN1_Object) -> int:
        """
        Sets the field name to asn1obj

        :param asn1obj:
        :return: 0 on failure, 1 on success
        """
        return m2.x509_name_entry_set_object(
            self.x509_name_entry, asn1obj._ptr()
        )

    def set_data(
        self, data: bytes, type: int = ASN1.MBSTRING_ASC
    ) -> int:
        """
        Sets the field name to asn1obj

        :param data: data in a binary form to be set
        :return: 0 on failure, 1 on success
        """
        return m2.x509_name_entry_set_data(
            self.x509_name_entry, type, data
        )

    def get_object(self) -> ASN1.ASN1_Object:
        return ASN1.ASN1_Object(
            m2.x509_name_entry_get_object(self.x509_name_entry)
        )

    def get_data(self) -> ASN1.ASN1_String:
        return ASN1.ASN1_String(
            m2.x509_name_entry_get_data(self.x509_name_entry)
        )

    def create_by_txt(self, field, type, entry, len):
        return m2.x509_name_entry_create_by_txt(
            self.x509_name_entry._ptr(), field, type, entry, len
        )


class X509_Name(object):
    """
    X509 Name
    """

    nid = {
        'C': m2.NID_countryName,
        'SP': m2.NID_stateOrProvinceName,
        'ST': m2.NID_stateOrProvinceName,
        'stateOrProvinceName': m2.NID_stateOrProvinceName,
        'L': m2.NID_localityName,
        'localityName': m2.NID_localityName,
        'O': m2.NID_organizationName,
        'organizationName': m2.NID_organizationName,
        'OU': m2.NID_organizationalUnitName,
        'organizationUnitName': m2.NID_organizationalUnitName,
        'CN': m2.NID_commonName,
        'commonName': m2.NID_commonName,
        'Email': m2.NID_pkcs9_emailAddress,
        'emailAddress': m2.NID_pkcs9_emailAddress,
        'serialNumber': m2.NID_serialNumber,
        'SN': m2.NID_surname,
        'surname': m2.NID_surname,
        'GN': m2.NID_givenName,
        'givenName': m2.NID_givenName,
    }

    m2_x509_name_free = m2.x509_name_free

    def __init__(
        self, x509_name: Optional[bytes] = None, _pyfree: int = 0
    ) -> None:
        """
        :param x509_name: this should be OpenSSL X509_NAME binary
        :param _pyfree:
        """
        if x509_name is not None:
            assert m2.x509_name_type_check(
                x509_name
            ), "'x509_name' type error"
            self.x509_name = x509_name
            self._pyfree = _pyfree
        else:
            self.x509_name = m2.x509_name_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_name_free(self.x509_name)

    def __str__(self) -> bytes:
        assert m2.x509_name_type_check(
            self.x509_name
        ), "'x509_name' type error"
        return m2.x509_name_oneline(self.x509_name)

    def __getattr__(self, attr: str) -> str:
        if attr in self.nid:
            assert m2.x509_name_type_check(
                self.x509_name
            ), "'x509_name' type error"
            out = m2.x509_name_by_nid(self.x509_name, self.nid[attr])
            return out.decode() if isinstance(out, bytes) else out

        if attr in self.__dict__:
            return self.__dict__[attr]

        raise AttributeError(self, attr)

    def __setattr__(self, attr: str, value: Union[str, bytes]) -> int:
        """
        :return: 1 for success of 0 if an error occurred.
        """
        if attr in self.nid:
            assert m2.x509_name_type_check(
                self.x509_name
            ), "'x509_name' type error"
            value = (
                value.encode() if isinstance(value, str) else value
            )
            return m2.x509_name_set_by_nid(
                self.x509_name, self.nid[attr], value
            )

        self.__dict__[attr] = value

    def __len__(self) -> int:
        return m2.x509_name_entry_count(self.x509_name)

    def __getitem__(self, idx: int) -> X509_Name_Entry:
        if not 0 <= idx < self.entry_count():
            raise IndexError("index out of range")
        return X509_Name_Entry(
            m2.x509_name_get_entry(self.x509_name, idx)
        )

    def __iter__(self):
        for i in range(self.entry_count()):
            yield self[i]

    def _ptr(self):
        assert m2.x509_name_type_check(
            self.x509_name
        ), "'x509_name' type error"
        return self.x509_name

    def add_entry_by_txt(
        self, field, type, entry, len, loc, set
    ) -> int:
        # entry_type: (str, int, bytes, int, int, int)
        """
        Add X509_Name field whose name is identified by its name.

        :param field: name of the entry
        :param type: use MBSTRING_ASC or MBSTRING_UTF8
               (or standard ASN1 type like V_ASN1_IA5STRING)
        :param entry: value
        :param len: buf_len of the entry
               (-1 and the length is computed automagically)

        The ``loc`` and ``set`` parameters determine where a new entry
        should be added.
        For almost all applications loc can be set to -1 and set to 0.
        This adds a new entry to the end of name as a single valued
        RelativeDistinguishedName (RDN).

        :param loc: determines the index where the new entry is
               inserted: if it is -1 it is appended.
        :param set: determines how the new type is added. If it is zero
               a new RDN is created.
               If set is -1 or 1 it is added to the previous or next RDN
               structure respectively. This will then be a multivalued
               RDN: since multivalues RDNs are very seldom used set is
               almost always set to zero.

        :return: 1 for success of 0 if an error occurred.
        """
        entry = entry.decode() if isinstance(entry, bytes) else entry
        return m2.x509_name_add_entry_by_txt(
            self.x509_name, field, type, entry, len, loc, set
        )

    def entry_count(self) -> int:
        return m2.x509_name_entry_count(self.x509_name)

    def get_entries_by_nid(self, nid: int) -> List[X509_Name_Entry]:
        """
        Retrieve the next index matching nid.

        :param nid: name of the entry (as m2.NID* constants)

        :return: list of X509_Name_Entry items
        """
        ret = []
        lastpos = -1

        while True:
            lastpos = m2.x509_name_get_index_by_nid(
                self.x509_name, nid, lastpos
            )
            if lastpos == -1:
                break

            ret.append(self[lastpos])

        return ret

    def as_text(
        self, indent: int = 0, flags: int = m2.XN_FLAG_COMPAT
    ) -> str:
        """
        as_text returns the name as a string.

        :param indent: Each line in multiline format is indented
                       by this many spaces.
        :param flags:  Flags that control how the output should be formatted.
        """
        assert m2.x509_name_type_check(
            self.x509_name
        ), "'x509_name' type error"
        buf = BIO.MemoryBuffer()
        m2.x509_name_print_ex(
            buf.bio_ptr(), self.x509_name, indent, flags
        )
        out = buf.read_all()
        return out.decode() if isinstance(out, bytes) else out

    def as_der(self) -> bytes:
        assert m2.x509_name_type_check(
            self.x509_name
        ), "'x509_name' type error"
        return m2.x509_name_get_der(self.x509_name)

    def as_hash(self) -> int:
        assert m2.x509_name_type_check(
            self.x509_name
        ), "'x509_name' type error"
        return m2.x509_name_hash(self.x509_name)


class X509(object):
    """
    X.509 Certificate
    """

    m2_x509_free = m2.x509_free

    def __init__(
        self, x509: Optional[bytes] = None, _pyfree: int = 0
    ) -> None:
        """
        :param x509: binary representation of
               the underlying OpenSSL X509 object.
        :param _pyfree:
        """
        if x509 is not None:
            assert m2.x509_type_check(x509), "'x509' type error"
            self.x509 = x509
            self._pyfree = _pyfree
        else:
            self.x509 = m2.x509_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_free(self.x509)

    def _ptr(self) -> bytes:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return self.x509

    def as_text(self) -> str:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf = BIO.MemoryBuffer()
        m2.x509_print(buf.bio_ptr(), self.x509)
        out = buf.read_all()
        return out.decode() if isinstance(out, bytes) else out

    def as_der(self) -> bytes:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.i2d_x509(self.x509)

    def as_pem(self) -> bytes:
        buf = BIO.MemoryBuffer()
        m2.x509_write_pem(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def save_pem(self, filename: Union[str, bytes]) -> int:
        """
        :param filename: name of the file to be loaded
        :return: 1 for success or 0 for failure
        """
        with BIO.openfile(filename, 'wb') as bio:
            return m2.x509_write_pem(bio.bio_ptr(), self.x509)

    def save(
        self, filename: Union[str, bytes], format: int = FORMAT_PEM
    ) -> int:
        """
        Saves X.509 certificate to a file. Default output
        format is PEM.

        :param filename: Name of the file the cert will be saved to.

        :param format: Controls what output format is used to save the cert.
                       Either FORMAT_PEM or FORMAT_DER to save in PEM or
                       DER format.  Raises a ValueError if an unknow
                       format is used.

        :return: 1 for success or 0 for failure
        """
        with BIO.openfile(filename, 'wb') as bio:
            if format == FORMAT_PEM:
                return m2.x509_write_pem(bio.bio_ptr(), self.x509)
            elif format == FORMAT_DER:
                return m2.i2d_x509_bio(bio.bio_ptr(), self.x509)
            else:
                raise ValueError(
                    "Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER"
                )

    def set_version(self, version: int) -> int:
        """
        Set version of the certificate.

        :param version: Version number.
        :return:        Returns 0 on failure.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_version(self.x509, version)

    def set_not_before(self, asn1_time: ASN1.ASN1_TIME) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_before(self.x509, asn1_time._ptr())

    def set_not_after(self, asn1_time: ASN1.ASN1_TIME) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_after(self.x509, asn1_time._ptr())

    def set_subject_name(self, name: X509_Name) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def set_issuer_name(self, name: X509_Name) -> int:
        """
        :return: 1 on success, 0 on failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_version(self) -> int:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_get_version(self.x509)

    def get_serial_number(self) -> ASN1.ASN1_Integer:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_get(asn1_integer)

    def set_serial_number(self, serial: ASN1.ASN1_Integer) -> int:
        """
        Set serial number.

        :param serial:  Serial number.

        :return 1 for success and 0 for failure.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        # This "magically" changes serial since asn1_integer
        # is C pointer to x509's internal serial number.
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_set(asn1_integer, serial)
        # XXX Or should I do this?
        # asn1_integer = m2.asn1_integer_new()
        # m2.asn1_integer_set(asn1_integer, serial)
        # return m2.x509_set_serial_number(self.x509, asn1_integer)

    def get_not_before(self) -> ASN1.ASN1_TIME:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        # ASN1_TIME_dup() as internal ref. depends on self being referenced
        ref = ASN1.ASN1_TIME(m2.x509_get_not_before(self.x509))
        out = ASN1.ASN1_TIME(_pyfree=1)
        out.set_datetime(ref.get_datetime())
        return out

    def get_not_after(self) -> ASN1.ASN1_TIME:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        # ASN1_TIME_dup() as internal ref. depends on self being referenced
        ref = ASN1.ASN1_TIME(m2.x509_get_not_after(self.x509))
        out = ASN1.ASN1_TIME(_pyfree=1)
        out.set_datetime(ref.get_datetime())
        if 'Bad time value' in str(out):
            raise X509Error(
                '''M2Crypto cannot handle dates after year 2050.
                See RFC 5280 4.1.2.5 for more information.
                '''
            )
        return out

    def get_pubkey(self) -> EVP.PKey:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return EVP.PKey(m2.x509_get_pubkey(self.x509), _pyfree=1)

    def set_pubkey(self, pkey: EVP.PKey) -> int:
        """
        Set the public key for the certificate

        :param pkey: Public key

        :return 1 for success and 0 for failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_pubkey(self.x509, pkey.pkey)

    def get_issuer(self) -> X509_Name:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_issuer_name(self.x509))

    def set_issuer(self, name: X509_Name) -> int:
        """
        Set issuer name.

        :param name:    subjectName field.

        :return 1 for success and 0 for failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_subject(self) -> X509_Name:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_subject_name(self.x509))

    def set_subject(self, name: X509_Name) -> int:
        """
        Set subject name.

        :param name:    subjectName field.

        :return 1 for success and 0 for failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def add_ext(self, ext: X509_Extension) -> int:
        """
        Add X509 extension to this certificate.

        :param ext:    Extension

        :return 1 for success and 0 for failure
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_add_ext(self.x509, ext.x509_ext, -1)

    def get_ext(self, name: str) -> X509_Extension:
        """
        Get X509 extension by name.

        :param name:    Name of the extension

        :return:       X509_Extension
        """
        # Optimizations to reduce attribute accesses
        m2x509_get_ext = m2.x509_get_ext
        m2x509_extension_get_name = m2.x509_extension_get_name
        x509 = self.x509

        name = name.encode() if isinstance(name, str) else name
        for i in range(m2.x509_get_ext_count(x509)):
            ext_ptr = m2x509_get_ext(x509, i)
            if m2x509_extension_get_name(ext_ptr) == name:
                return X509_Extension(ext_ptr, _pyfree=0)

        raise LookupError

    def get_ext_at(self, index: int) -> X509_Extension:
        """
        Get X509 extension by index.

        :param index:    Name of the extension

        :return:        X509_Extension
        """
        if index < 0 or index >= self.get_ext_count():
            raise IndexError

        return X509_Extension(
            m2.x509_get_ext(self.x509, index), _pyfree=0
        )

    def get_ext_count(self) -> int:
        """
        Get X509 extension count.
        """
        return m2.x509_get_ext_count(self.x509)

    def sign(self, pkey: EVP.PKey, md: str) -> int:
        """
        Sign the certificate.

        :param pkey: Public key

        :param md:   Message digest algorithm to use for signing,
                     for example 'sha1'.

        :return int
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError('unknown message digest', md)
        return m2.x509_sign(self.x509, pkey.pkey, mda())

    def verify(self, pkey: Optional[EVP.PKey] = None) -> int:
        assert m2.x509_type_check(self.x509), "'x509' type error"
        if pkey:
            return m2.x509_verify(self.x509, pkey.pkey)
        else:
            return m2.x509_verify(self.x509, self.get_pubkey().pkey)

    def check_ca(self) -> int:
        """
        Check if the certificate is a Certificate Authority (CA) certificate.

        :return: 0 if the certificate is not CA, nonzero otherwise.

        :requires: OpenSSL 0.9.8 or newer
        """
        return m2.x509_check_ca(self.x509)

    def check_purpose(self, id: int, ca: int) -> int:
        """
        Check if the certificate's purpose matches the asked purpose.

        :param id: Purpose id. See X509_PURPOSE_* constants.

        :param ca: 1 if the certificate should be CA, 0 otherwise.

        :return: 0 if the certificate purpose does not match, nonzero
                 otherwise.
        """
        return m2.x509_check_purpose(self.x509, id, ca)

    def get_fingerprint(self, md: str = 'md5') -> str:
        """
        Get the fingerprint of the certificate.

        :param md: Message digest algorithm to use.

        :return:   String containing the fingerprint in hex format.
        """
        der = self.as_der()
        md = EVP.MessageDigest(md)
        md.update(der)
        digest = md.final()
        return binascii.hexlify(digest).upper().decode()


def load_cert(file, format: int = FORMAT_PEM) -> X509:
    """
    Load certificate from file.

    :param file: Name of file containing certificate in either DER or
                 PEM format.

    :param format: Describes the format of the file to be loaded,
                   either PEM or DER.

    :return: M2Crypto.X509.X509 object.
    """
    with BIO.openfile(file) as bio:
        if format == FORMAT_PEM:
            return load_cert_bio(bio)
        elif format == FORMAT_DER:
            cptr = m2.d2i_x509(bio._ptr())
            return X509(cptr, _pyfree=1)
        else:
            raise ValueError(
                "Unknown format. Must be either FORMAT_DER or FORMAT_PEM"
            )


def load_cert_bio(bio: BIO.BIO, format: int = FORMAT_PEM) -> X509:
    """
    Load certificate from a bio.

    :param bio: BIO pointing at a certificate in either DER or PEM format.

    :param format: Describes the format of the cert to be loaded,
                   either PEM or DER (via constants FORMAT_PEM
                   and FORMAT_FORMAT_DER)

    :return: M2Crypto.X509.X509 object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509(bio._ptr())
    else:
        raise ValueError(
            "Unknown format. Must be either FORMAT_DER or FORMAT_PEM"
        )
    return X509(cptr, _pyfree=1)


def load_cert_string(
    cert_str: Union[str, bytes], format: int = FORMAT_PEM
) -> X509:
    """
    Load certificate from a cert_str.

    :param cert_str: String containing a certificate in either
                     DER or PEM format.

    :param format: Describes the format of the cert to be loaded,
                   either PEM or DER (via constants FORMAT_PEM
                   and FORMAT_FORMAT_DER)

    :return: M2Crypto.X509.X509 object.
    """
    cert_str = (
        cert_str.encode() if isinstance(cert_str, str) else cert_str
    )
    bio = BIO.MemoryBuffer(cert_str)
    return load_cert_bio(bio, format)


def load_cert_der_string(cert_str: Union[str, bytes]) -> X509:
    """
    Load certificate from a cert_str.

    :param cert_str: String containing a certificate in DER format.

    :return: M2Crypto.X509.X509 object.
    """
    cert_str = (
        cert_str.encode() if isinstance(cert_str, str) else cert_str
    )
    bio = BIO.MemoryBuffer(cert_str)
    cptr = m2.d2i_x509(bio._ptr())
    return X509(cptr, _pyfree=1)


class X509_Stack(object):
    """
    X509 Stack

    :warning: Do not modify the underlying OpenSSL stack
              except through this interface, or use any OpenSSL
              functions that do so indirectly. Doing so will get the
              OpenSSL stack and the internal pystack of this class out
              of sync, leading to python memory leaks, exceptions or
              even python crashes!
    """

    m2_sk_x509_free = m2.sk_x509_free

    def __init__(
        self,
        stack: Optional[bytes] = None,
        _pyfree: int = 0,
        _pyfree_x509: int = 0,
    ) -> None:
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
            self.pystack = (
                []
            )  # This must be kept in sync with self.stack
            num = m2.sk_x509_num(self.stack)
            for i in range(num):
                self.pystack.append(
                    X509(
                        m2.sk_x509_value(self.stack, i),
                        _pyfree=_pyfree_x509,
                    )
                )
        else:
            self.stack = m2.sk_x509_new_null()
            self._pyfree = 1
            self.pystack = (
                []
            )  # This must be kept in sync with self.stack

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_sk_x509_free(self.stack)

    def __len__(self) -> int:
        assert m2.sk_x509_num(self.stack) == len(self.pystack)
        return len(self.pystack)

    def __getitem__(self, idx: int) -> X509:
        return self.pystack[idx]

    def __iter__(self):
        return iter(self.pystack)

    def _ptr(self):
        return self.stack

    def push(self, x509: X509) -> int:
        """
        push an X509 certificate onto the stack.

        :param x509: X509 object.

        :return: The number of X509 objects currently on the stack.
        """
        self.pystack.append(x509)
        ret = m2.sk_x509_push(self.stack, x509._ptr())
        assert ret == len(self.pystack)
        return ret

    def pop(self) -> X509:
        """
        pop a certificate from the stack.

        :return: X509 object that was popped, or None if there is
                 nothing to pop.
        """
        x509_ptr = m2.sk_x509_pop(self.stack)
        if x509_ptr is None:
            assert len(self.pystack) == 0
            return None
        return self.pystack.pop()

    def as_der(self) -> bytes:
        """
        Return the stack as a DER encoded string
        """
        return m2.get_der_encoding_stack(self.stack)


class X509_Store_Context(object):
    """
    X509 Store Context
    """

    m2_x509_store_ctx_free = m2.x509_store_ctx_free

    def __init__(
        self, x509_store_ctx: bytes, _pyfree: int = 0
    ) -> None:
        """

        :param x509_store_ctx: binary data for
              OpenSSL X509_STORE_CTX type
        """
        self.ctx = x509_store_ctx
        self._pyfree = _pyfree

    def __del__(self) -> None:
        # see BIO.py - unbalanced __init__ / __del__
        if not hasattr(self, '_pyfree'):
            pass  # print("OOPS")
        elif self._pyfree:
            self.m2_x509_store_ctx_free(self.ctx)

    def _ptr(self):
        return self.ctx

    def get_current_cert(self) -> X509:
        """
        Get current X.509 certificate.

        :warning: The returned certificate is NOT refcounted, so you can not
                  rely on it being valid once the store context goes
                  away or is modified.
        """
        return X509(
            m2.x509_store_ctx_get_current_cert(self.ctx), _pyfree=0
        )

    def get_error(self) -> int:
        """
        Get error code.
        """
        return m2.x509_store_ctx_get_error(self.ctx)

    def get_error_depth(self) -> int:
        """
        Get error depth.
        """
        return m2.x509_store_ctx_get_error_depth(self.ctx)

    def get1_chain(self) -> X509_Stack:
        """
        Get certificate chain.

        :return: Reference counted (i.e. safe to use even after the store
                 context goes away) stack of certificates in the
                 chain as X509_Stack.
        """
        return X509_Stack(
            m2.x509_store_ctx_get1_chain(self.ctx), 1, 1
        )


def x509_store_default_cb(ok: int, ctx: X509_Store_Context) -> int:
    return ok


class X509_Store(object):
    """
    X509 Store
    """

    m2_x509_store_free = m2.x509_store_free

    def __init__(
        self, store: Optional[bytes] = None, _pyfree: int = 0
    ) -> None:
        """
        :param store: binary data for OpenSSL X509_STORE_CTX type.
        """
        if store is not None:
            self.store = store
            self._pyfree = _pyfree
        else:
            self.store = m2.x509_store_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_store_free(self.store)

    def _ptr(self):
        return self.store

    def load_info(self, file: Union[str, bytes]) -> int:
        """
        :param file: filename

        :return: 1 on success, 0 on failure
        """
        ret = m2.x509_store_load_locations(self.store, file)
        return ret

    load_locations = load_info

    def add_x509(self, x509: X509) -> int:
        return m2.x509_store_add_cert(self.store, x509._ptr())

    def set_verify_cb(
        self, callback: Optional[callable] = None
    ) -> None:
        """
        Set callback which will be called when the store is verified.
        Wrapper over OpenSSL X509_STORE_set_verify_cb().

        :param callback:    Callable to specify verification options.
                            Type of the callable must be:
                            (int, X509_Store_Context) -> int.
                            If None: set the standard options.

        :note: compile-time or run-time errors in the callback would result
               in mysterious errors during verification, which could be hard
               to trace.

        :note: Python exceptions raised in callbacks do not propagate to
               verify() call.

        :return: None
        """
        if callback is None:
            return self.set_verify_cb(x509_store_default_cb)

        if not callable(callback):
            raise X509Error("set_verify(): callback is not callable")
        return m2.x509_store_set_verify_cb(self.store, callback)

    add_cert = add_x509

    def set_flags(self, flags: int) -> int:
        """
        Set the verification flags for the X509Store
        Wrapper over OpenSSL X509_STORE_set_flags()

        :param flags: `VERIFICATION FLAGS` section of the
                      X509_VERIFY_PARAM_set_flags man page has
                      a complete description of values the flags
                      parameter can take.
                      Their M2Crypto equivalent is transformed following
                      the pattern: "X509_V_FLAG_XYZ" -> lowercase("VERIFY_XYZ")
        """
        return m2.x509_store_set_flags(self.store, flags)


def new_stack_from_der(der_string: bytes) -> X509_Stack:
    """
    Create a new X509_Stack from DER string.

    :return: X509_Stack
    """
    der_string = (
        der_string.encode()
        if isinstance(der_string, str)
        else der_string
    )
    stack_ptr = m2.make_stack_from_der_sequence(der_string)
    return X509_Stack(stack_ptr, 1, 1)


class Request(object):
    """
    X509 Certificate Request.
    """

    m2_x509_req_free = m2.x509_req_free

    def __init__(
        self, req: Optional[int] = None, _pyfree: int = 0
    ) -> None:
        if req is not None:
            self.req = req
            self._pyfree = _pyfree
        else:
            self.req = m2.x509_req_new()
            m2.x509_req_set_version(self.req, 0)
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_req_free(self.req)

    def as_text(self) -> str:
        buf = BIO.MemoryBuffer()
        m2.x509_req_print(buf.bio_ptr(), self.req)
        out = buf.read_all()
        return out.decode() if isinstance(out, bytes) else out

    def as_pem(self) -> bytes:
        buf = BIO.MemoryBuffer()
        m2.x509_req_write_pem(buf.bio_ptr(), self.req)
        return buf.read_all()

    def as_der(self) -> bytes:
        buf = BIO.MemoryBuffer()
        m2.i2d_x509_req_bio(buf.bio_ptr(), self.req)
        return buf.read_all()

    def save_pem(self, filename: Union[str, bytes]) -> int:
        with BIO.openfile(filename, 'wb') as bio:
            return m2.x509_req_write_pem(bio.bio_ptr(), self.req)

    def save(
        self, filename: Union[str, bytes], format: int = FORMAT_PEM
    ) -> int:
        """
        Saves X.509 certificate request to a file. Default output
        format is PEM.

        :param filename: Name of the file the request will be s: aved to.

                       request. Either FORMAT_PEM or FORMAT_DER to save
                       in PEM or DER format. Raises V:  a lueError if an
                       unknown format is used.

        :return: 1 for success, 0 for failure.
                 The error code can be obtained by ERR_get_error.
        """
        with BIO.openfile(filename, 'wb') as bio:
            if format == FORMAT_PEM:
                return m2.x509_req_write_pem(bio.bio_ptr(), self.req)
            elif format == FORMAT_DER:
                return m2.i2d_x509_req_bio(bio.bio_ptr(), self.req)
            else:
                raise ValueError(
                    "Unknown filetype. Must be either FORMAT_DER or FORMAT_PEM"
                )

    def get_pubkey(self) -> EVP.PKey:
        """
        Get the public key for the request.

        :return:     Public key from the request.
        """
        return EVP.PKey(m2.x509_req_get_pubkey(self.req), _pyfree=1)

    def set_pubkey(self, pkey: EVP.PKey) -> int:
        """
        Set the public key for the request.

        :param pkey: Public key

        :return:     Return 1 for success and 0 for failure.
        """
        return m2.x509_req_set_pubkey(self.req, pkey.pkey)

    def get_version(self) -> int:
        """
        Get version.

        :return:        Returns version.
        """
        return m2.x509_req_get_version(self.req)

    def set_version(self, version: int) -> int:
        """
        Set version.

        :param version: Version number.
        :return:        Returns 0 on failure.
        """
        return m2.x509_req_set_version(self.req, version)

    def get_subject(self) -> X509_Name:
        return X509_Name(m2.x509_req_get_subject_name(self.req))

    def set_subject_name(self, name: X509_Name) -> int:
        """
        Set subject name.

        :param name:    subjectName field.
        :return:    1 for success and 0 for failure
        """
        return m2.x509_req_set_subject_name(self.req, name.x509_name)

    set_subject = set_subject_name

    def add_extensions(self, ext_stack: X509_Extension_Stack) -> int:
        """
        Add X509 extensions to this request.

        :param ext_stack: Stack of extensions to add.
        :return: 1 for success and 0 for failure
        """
        return m2.x509_req_add_extensions(self.req, ext_stack._ptr())

    def verify(self, pkey: EVP.PKey) -> int:
        """

        :param pkey: PKey to be verified
        :return: 1 for success and 0 for failure
        """
        return m2.x509_req_verify(self.req, pkey.pkey)

    def sign(self, pkey: EVP.PKey, md: str) -> int:
        """

        :param pkey: PKey to be signed
        :param md: used algorigthm
        :return: 1 for success and 0 for failure
        """
        mda = getattr(m2, md, None)
        if mda is None:
            raise ValueError('unknown message digest', md)
        return m2.x509_req_sign(self.req, pkey.pkey, mda())


def load_request(
    file: Union[str, bytes], format: int = FORMAT_PEM
) -> Request:
    """
    Load certificate request from file.

    :param file: Name of file containing certificate request in
                 either PEM or DER format.
    :param format: Describes the format of the file to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)
    :return: Request object.
    """
    with BIO.openfile(file) as f:
        if format == FORMAT_PEM:
            cptr = m2.x509_req_read_pem(f.bio_ptr())
        elif format == FORMAT_DER:
            cptr = m2.d2i_x509_req(f.bio_ptr())
        else:
            raise ValueError(
                "Unknown filetype. Must be either FORMAT_PEM or FORMAT_DER"
            )

    return Request(cptr, 1)


def load_request_bio(
    bio: BIO.BIO, format: int = FORMAT_PEM
) -> Request:
    """
    Load certificate request from a bio.

    :param bio: BIO pointing at a certificate request in
                either DER or PEM format.
    :param format: Describes the format of the request to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)
    :return: M2Crypto.X509.Request object.
    """
    if format == FORMAT_PEM:
        cptr = m2.x509_req_read_pem(bio._ptr())
    elif format == FORMAT_DER:
        cptr = m2.d2i_x509_req(bio._ptr())
    else:
        raise ValueError(
            "Unknown format. Must be either FORMAT_DER or FORMAT_PEM"
        )

    return Request(cptr, _pyfree=1)


def load_request_string(
    cert_str: Union[str, bytes], format: int = FORMAT_PEM
) -> Request:
    """
    Load certificate request from a cert_str.

    :param cert_str: String containing a certificate request in
                     either DER or PEM format.
    :param format: Describes the format of the request to be loaded,
                   either PEM or DER. (using constants FORMAT_PEM
                   and FORMAT_DER)

    :return: M2Crypto.X509.Request object.
    """
    cert_str = (
        cert_str.encode() if isinstance(cert_str, str) else cert_str
    )
    bio = BIO.MemoryBuffer(cert_str)
    return load_request_bio(bio, format)


def load_request_der_string(cert_str: Union[str, bytes]) -> Request:
    """
    Load certificate request from a cert_str.

    :param cert_str: String containing a certificate request in DER format.
    :return: M2Crypto.X509.Request object.
    """
    cert_str = (
        cert_str.encode() if isinstance(cert_str, str) else cert_str
    )
    bio = BIO.MemoryBuffer(cert_str)
    return load_request_bio(bio, FORMAT_DER)


class CRL(object):
    """
    X509 Certificate Revocation List
    """

    m2_x509_crl_free = m2.x509_crl_free

    def __init__(
        self, crl: Optional[bytes] = None, _pyfree: int = 0
    ) -> None:
        """

        :param crl: binary representation of
               the underlying OpenSSL X509_CRL object.
        """
        if crl is not None:
            self.crl = crl
            self._pyfree = _pyfree
        else:
            self.crl = m2.x509_crl_new()
            self._pyfree = 1

    def __del__(self) -> None:
        if getattr(self, '_pyfree', 0):
            self.m2_x509_crl_free(self.crl)

    def as_text(self) -> str:
        """
        Return CRL in PEM format in a string.

        :return: String containing the CRL in PEM format.
        """
        buf = BIO.MemoryBuffer()
        m2.x509_crl_print(buf.bio_ptr(), self.crl)
        out = buf.read_all()
        return out.decode() if isinstance(out, bytes) else out


def load_crl(file: Union[str, bytes]) -> CRL:
    """
    Load CRL from file.

    :param file: Name of file containing CRL in PEM format.

    :return: M2Crypto.X509.CRL object.
    """
    with BIO.openfile(file) as f:
        cptr = m2.x509_crl_read_pem(f.bio_ptr())

    return CRL(cptr, 1)
