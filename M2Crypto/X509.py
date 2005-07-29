"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2005 OSAF. All Rights Reserved.
Author: Heikki Toivonen
"""

RCS_id='$Id$'

# M2Crypto
from M2Crypto import ASN1, BIO, Err, EVP
import m2

class X509Error(Exception): pass

m2.x509_init(X509Error)

V_OK = m2.X509_V_OK

def new_extension(name, value, critical=0, _pyfree=1):
    """
    Create new X509_Extension instance.
    """
    x509_ext_ptr = m2.x509v3_ext_conf(None, None, name, value)
    x509_ext = X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext


class X509_Extension:
    """
    X509 Extension
    """
    def __init__(self, x509_ext_ptr=None, _pyfree=1):
        self.x509_ext = x509_ext_ptr
        self._pyfree = _pyfree

    def __del__(self):
        if self._pyfree and self.x509_ext:
            m2.x509_extension_free(self.x509_ext)

    def _ptr(self):
        return self.x509_ext

    def set_critical(self, critical=1):
        """
        Mark this extension critical or noncritical. By default an
        extension is not critical.

        @type critical:  int
        @param critical: Nonzero sets this extension as critical.
                         Calling this method without arguments will
                         set this extension to critical.
        """
        return m2.x509_extension_set_critical(self.x509_ext, critical)

    def get_critical(self):
        """
        Return whether or not this is a critical extension.

        @rtype:   int
        @return:  Nonzero if this is a critical extension.
        """
        return m2.x509_extension_get_critical(self.x509_ext)

    def get_name(self):
        """
        Get the extension name, for example 'subjectAltName'.
        """
        return m2.x509_extension_get_name(self.x509_ext)

    def get_value(self):
        """
        Get the extension value, for example 'DNS:www.example.com'.
        """
        buf=BIO.MemoryBuffer()
        m2.x509_ext_print(buf.bio_ptr(), self.x509_ext, 0, 0)
        return buf.read_all()


class X509_Extension_Stack:
    """
    X509 Extension Stack
    """
    def __init__(self, stack=None, _pyfree=0):
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
        else:
            self.stack = m2.sk_x509_extension_new_null()
            self._pyfree = 1
        self._refkeeper = {}

    def __del__(self):
        if self._pyfree:
            m2.sk_x509_extension_free(self.stack)

    def __len__(self):
        return m2.sk_x509_extension_num(self.stack)

    def __getitem__(self, idx):
        if idx < 0 or idx >= m2.sk_x509_extension_num(self.stack):
            raise IndexError

        return X509_Extension(m2.sk_x509_extension_value(self.stack, idx),
                              _pyfree=0)
 
    def _ptr(self):
        return self.stack

    def push(self, x509_ext):
        """
        Push X509_Extension object onto the stack.

        @type x509_ext: M2Crypto.X509.X509_Extension
        @param x509_ext: X509_Extension object to be pushed onto the stack.
        """
        self._refkeeper[x509_ext._ptr()] = x509_ext
        return m2.sk_x509_extension_push(self.stack, x509_ext._ptr())

    def pop(self):
        """
        Pop X509_Extension object from the stack.
        
        @return: X509_Extension popped
        """
        # XXX This method does not yet work. See also X509_Stack.
        if m2.sk_x509_extension_num(self.stack) <= 0:
            return None
        x509_ext_ptr = m2.sk_x509_extension_pop(self.stack)
        del self._refkeeper[x509_ext_ptr]
        return X509_Extension(x509_ext_ptr)


class X509_Name_Entry:
    """
    X509 Name Entry
    """
    def __init__(self, x509_name_entry, _pyfree=0):
        self.x509_name_entry = x509_name_entry
        self._pyfree = _pyfree

    def __del__(self):
        try:
            if self._pyfree:
                m2.x509_name_entry_free(self.x509_name_entry)
        except AttributeError:
            pass    

    def _ptr(self):
        return self.x509_name_entry

    def set_object(self, asn1obj):
        return m2.x509_name_entry_set_object( self.x509_name_entry, asn1obj._ptr() )

    def create_by_txt( self, field, type, entry, len):
        return m2.x509_name_entry_create_by_txt( self.x509_name_entry._ptr(), field, type, entry, len )

    def as_text(self):
        buf = BIO.MemoryBuffer()
        m2.x509_name_entry_print( buf.bio_ptr(), self.x509_name_entry )
        return buf.read_all()


class X509_Name:
    """
    X509 Name
    """

    nid = {'C'                      : m2.NID_countryName,
           'SP'                     : m2.NID_stateOrProvinceName,
           'ST'                     : m2.NID_stateOrProvinceName,
           'stateOrProvinceName'    : m2.NID_stateOrProvinceName,
           'L'                      : m2.NID_localityName,
           'localityName'           : m2.NID_localityName,
           'O'                      : m2.NID_organizationName,
           'organizationName'       : m2.NID_organizationName,
           'OU'                     : m2.NID_organizationalUnitName,
           'organizationUnitName'   : m2.NID_organizationalUnitName,
           'CN'                     : m2.NID_commonName,
           'commonName'             : m2.NID_commonName,
           'Email'                  : m2.NID_pkcs9_emailAddress,
           'emailAddress'           : m2.NID_pkcs9_emailAddress
           }

    def __init__(self, x509_name=None, _pyfree=0):
        if x509_name is not None:
            assert m2.x509_name_type_check(x509_name), "'x509_name' type error"
            self.x509_name = x509_name
            self._pyfree = _pyfree
        else:
            self.x509_name = m2.x509_name_new ()
            self._pyfree = 1

    def __del__(self):
        try:
            if self._pyfree:
                m2.x509_name_free(self.x509_name)
        except AttributeError:
            pass

    def __str__(self):
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
        return m2.x509_name_oneline(self.x509_name)

    def __getattr__(self, attr):
        if attr in self.nid.keys():
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
            return m2.x509_name_by_nid(self.x509_name, self.nid[attr])
        else:
            raise AttributeError, (self, attr)

    def __setattr__(self, attr, value):
        if attr in self.nid.keys():
            assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
            return m2.x509_name_set_by_nid(self.x509_name, self.nid[attr], value)
        else:
            self.__dict__[attr] = value

    def _ptr(self):
        #assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error" 
        return self.x509_name

    def add_entry_by_txt( self, field, type, entry, len, loc, set):
        return m2.x509_name_add_entry_by_txt( self.x509_name, field, type, entry, len, loc, set )

    def entry_count( self ):
        return m2.x509_name_entry_count( self.x509_name )

    def as_text(self):
        assert m2.x509_name_type_check(self.x509_name), "'x509_name' type error"
        buf=BIO.MemoryBuffer()
        m2.x509_name_print(buf.bio_ptr(), self.x509_name, 0)
        return buf.read_all()


class X509:
    """
    X.509 Certificate
    """
    def __init__(self, x509=None, _pyfree=0):
        if x509 is not None:
            assert m2.x509_type_check(x509), "'x509' type error"
            self.x509 = x509
            self._pyfree = _pyfree
        else:
            self.x509 = m2.x509_new ()
            self._pyfree = 1

    def __del__(self):
        try:
            if self._pyfree:
                m2.x509_free(self.x509)
        except AttributeError:
            pass

    def _ptr(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return self.x509

    def as_text(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf=BIO.MemoryBuffer()
        m2.x509_print(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def as_der(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        buf=BIO.MemoryBuffer()
        m2.i2d_x509(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def as_pem(self):
        buf=BIO.MemoryBuffer()
        m2.x509_write_pem(buf.bio_ptr(), self.x509)
        return buf.read_all()

    def save_pem(self, filename):
        """
        save_pem
        """
        bio=BIO.openfile(filename, 'wb')
        return m2.x509_write_pem(bio.bio_ptr(), self.x509)

    def set_version(self, version):
        """
        Set version.

        @type version:  int
        @param version: Version number.
        @rtype:         int
        @return:        Returns 0 on failure.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_version(self.x509, version)

    def set_not_before(self, asn1_utctime):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_before(self.x509, asn1_utctime._ptr())

    def set_not_after(self, asn1_utctime):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_not_after(self.x509, asn1_utctime._ptr())

    def set_subject_name(self, name):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def set_issuer_name(self, name):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_version(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_get_version(self.x509)

    def get_serial_number(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_get(asn1_integer)

    def set_serial_number(self, serial):
        """
        Set serial number.

        @type serial:   int
        @param serial:  Serial number.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        # This "magically" changes serial since asn1_integer
        # is C pointer to x509's internal serial number.
        asn1_integer = m2.x509_get_serial_number(self.x509)
        return m2.asn1_integer_set(asn1_integer, serial)
        # XXX Or should I do this?
        #asn1_integer = m2.asn1_integer_new()
        #m2.asn1_integer_set(asn1_integer, serial)
        #return m2.x509_set_serial_number(self.x509, asn1_integer)

    def get_not_before(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return ASN1.ASN1_UTCTIME(m2.x509_get_not_before(self.x509))

    def get_not_after(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return ASN1.ASN1_UTCTIME(m2.x509_get_not_after(self.x509))

    def get_pubkey(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return EVP.PKey(m2.x509_get_pubkey(self.x509), _pyfree=1)

    def set_pubkey(self, pkey):
        """
        Set the public key for the certificate

        @type pkey:  EVP_PKEY
        @param pkey: Public key
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_pubkey(self.x509, pkey.pkey)

    def get_issuer(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_issuer_name(self.x509))

    def set_issuer(self, name):
        """
        Set issuer name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_issuer_name(self.x509, name.x509_name)

    def get_subject(self):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return X509_Name(m2.x509_get_subject_name(self.x509))

    def set_subject(self, name):
        """
        Set subject name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_set_subject_name(self.x509, name.x509_name)

    def add_ext(self, ext):
        """
        Add X509 extension to this certificate.

        @type ext:     X509_Extension
        @param ext:    Extension
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        return m2.x509_add_ext(self.x509, ext.x509_ext, -1)

    def get_ext(self, name):
        """
        Get X509 extension by name.

        @type name:    Name of the extension
        @param name:   str
        @return:       X509_Extension
        """
        for i in range(self.get_ext_count()):
            ext = self.get_ext_at(i)
            if ext.get_name() == name:
                return ext

        raise LookupError

    def get_ext_at(self, index):
        """
        Get X509 extension by index.

        @type index:    Name of the extension
        @param index:   int
        @return:        X509_Extension
        """
        if index < 0 or index >= self.get_ext_count():
            raise IndexError
        
        return X509_Extension(m2.x509_get_ext(self.x509, index),
                              _pyfree=0)

    def get_ext_count(self):
        """
        Get X509 extension count.
        """
        return m2.x509_get_ext_count(self.x509)        

    def sign(self, pkey, md):
        """
        Sign the certificate.

        @type pkey:  EVP_PKEY
        @param pkey: Public key
        @type md:    str
        @param md:   Message digest algorithm to use for signing,
                     for example 'sha1'.
        """
        assert m2.x509_type_check(self.x509), "'x509' type error"
        mda = getattr(m2, md)
        if not mda:
            raise ValueError, ('unknown message digest', md)
        return m2.x509_sign(self.x509, pkey.pkey, mda())

    def verify(self, pkey=None):
        assert m2.x509_type_check(self.x509), "'x509' type error"
        if pkey:
            return m2.x509_verify(self.x509, pkey.pkey)
        else:
            return m2.x509_verify(self.x509, m2.x509_get_pubkey(self.x509))
            
    def check_ca(self):
        """
        Check if the certificate is a Certificate Authority (CA) certificate.
        
        @return: 0 if the certificate is not CA, nonzero otherwise.
        """
        #return m2.x509_check_ca(self.x509)
        raise NotImplementedError
        
    def check_purpose(self, id, ca):
        """
        Check if the certificate's purpose matches the asked purpose.
        
        @param id: Purpose id. See X509_PURPOSE_* constants.
        @param ca: 1 if the certificate should be CA, 0 otherwise.
        @return: 0 if the certificate purpose does not match, nonzero otherwise.
        """
        return m2.x509_check_purpose(self.x509, id, ca)


def load_cert(file):
    """
    Load certificate from file.

    @type file: string
    @param file: Name of file containing certificate in PEM format.

    @rtype: M2Crypto.X509.X509
    @return: M2Crypto.X509.X509 object.
    """
    bio = BIO.openfile(file)
    return load_cert_bio(bio)


def load_cert_bio(bio):
    return X509(m2.x509_read_pem(bio._ptr()), 1)


def load_cert_string(string):
    bio = BIO.MemoryBuffer(string)
    return load_cert_bio(bio)


class X509_Store_Context:
    """
    X509 Store Context
    """
    def __init__(self, x509_store_ctx, _pyfree=0):
        self.ctx = x509_store_ctx
        self._pyfree = _pyfree

    def __del__(self):
        if self._pyfree:
            m2.x509_store_ctx_free(self.ctx)
            
    def _ptr(self):
        return self.ctx
            
    def get_current_cert(self):
        """
        Get current X.509 certificate.
        
        @warning: The returned certificate is NOT refcounted, so you can not
        rely on it being valid once the store context goes away or is modified.
        """
        return X509(m2.x509_store_ctx_get_current_cert(self.ctx), _pyfree=0)

    def get_error(self):
        """
        Get error code.
        """
        return m2.x509_store_ctx_get_error(self.ctx)
        
    def get_error_depth(self):
        """
        Get error depth.
        """
        return m2.x509_store_ctx_get_error_depth(self.ctx)
        

class X509_Store:
    """
    X509 Store
    """
    def __init__(self, store=None, _pyfree=0):
        if store is not None:
            self.store = store
            self._pyfree = _pyfree
        else:
            self.store = m2.x509_store_new()
            self._pyfree = 1

    def __del__(self):
        if self._pyfree:
            m2.x509_store_free(self.store)

    def _ptr(self):
        return self.store

    def load_info(self, file):
        m2.x509_store_load_locations(self.store, file)

    load_locations = load_info
                 
    def add_x509(self, x509):
        assert isinstance(x509, X509)
        return m2.x509_store_add_cert(self.store, x509._ptr())
        
    add_cert = add_x509


class X509_Stack:
    """
    X509 Stack
    """
    def __init__(self, stack=None, _pyfree=0):
        if stack is not None:
            self.stack = stack
            self._pyfree = _pyfree
        else:
            self.stack = m2.sk_x509_new_null()
            self._pyfree = 1
        self._refkeeper = {}

    def __del__(self):
        if self._pyfree:
            m2.sk_x509_free(self.stack)

    def __len__(self):
        return m2.sk_x509_num(self.stack)

    def __getitem__(self, idx):
        if idx < 0 or idx >= m2.sk_x509_num(self.stack):
            raise IndexError, 'index out of range'
        v=m2.sk_x509_value(self.stack, idx)
        return X509(v)

    def _ptr(self):
        return self.stack

    def push(self, x509):
        assert isinstance(x509, X509)
        self._refkeeper[x509._ptr()] = x509
        return m2.sk_x509_push(self.stack, x509._ptr())

    def pop(self):
        # See also X509_Extension_Stack. This method should return something.
        x509_ptr = m2.sk_x509_pop(self.stack)
        del self._refkeeper[x509_ptr]


class Request:
    """
    X509 Certificate Request.
    """
    def __init__(self, req=None, _pyfree=0):
        if req is not None:
            self.req = req
            self._pyfree = _pyfree
        else:
            self.req = m2.x509_req_new()
            self._pyfree = 1

    def __del__(self):
        if self._pyfree:
            m2.x509_req_free(self.req)

    def as_text(self):
        buf=BIO.MemoryBuffer()
        m2.x509_req_print(buf.bio_ptr(), self.req)
        return buf.read_all()

    def as_pem(self):
        buf=BIO.MemoryBuffer()
        m2.x509_req_write_pem(buf.bio_ptr(), self.req)
        return buf.read_all()

    def save_pem(self, filename):
        bio=BIO.openfile(filename, 'wb')
        return m2.x509_req_write_pem(bio.bio_ptr(), self.req)

    def get_pubkey(self):
        """
        Get the public key for the request.

        @rtype:      EVP_PKEY
        @return:     Public key from the request.
        """
        return EVP.PKey(m2.x509_req_get_pubkey(self.req), _pyfree=1)

    def set_pubkey(self, pkey):
        """
        Set the public key for the request.

        @type pkey:  EVP_PKEY
        @param pkey: Public key

        @rtype:      int
        @return:     Return 1 for success and 0 for failure.
        """
        return m2.x509_req_set_pubkey( self.req, pkey.pkey )

    def get_version(self):
        """
        Get version.

        @rtype:         int
        @return:        Returns version.
        """
        return m2.x509_req_get_version(self.req)

    def set_version(self, version):
        """
        Set version.

        @type version:  int
        @param version: Version number.
        @rtype:         int
        @return:        Returns 0 on failure.
        """
        return m2.x509_req_set_version( self.req, version )

    def get_subject(self):
        return X509_Name(m2.x509_req_get_subject_name( self.req ))

    def set_subject_name(self, name):
        """
        Set subject name.

        @type name:     X509_Name
        @param name:    subjectName field.
        """
        return m2.x509_req_set_subject_name( self.req, name.x509_name )

    def add_extensions(self, ext_stack):
        """
        Add X509 extensions to this request.

        @type ext_stack:  X509_Extension_Stack
        @param ext_stack: Stack of extensions to add.
        """
        return m2.x509_req_add_extensions(self.req, ext_stack._ptr())

    def verify(self, pkey):
        return m2.x509_req_verify(self.req, pkey.pkey)

    def sign(self, pkey, md):
        mda = getattr(m2, md)
        if not mda:
            raise ValueError, ('unknown message digest', md)
        return m2.x509_req_sign(self.req, pkey.pkey, mda())


def load_request(file):
    """
    Load certificate request from file.

    @type file: string
    @param file: Name of file containing certificate request in PEM format.

    @rtype: M2Crypto.X509.Request
    @return: M2Crypto.X509.Request object.
    """
    f=BIO.openfile(file)
    cptr=m2.x509_req_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return Request(cptr, 1)


class CRL:
    """
    X509 Certificate Revocation List
    """
    def __init__(self, crl=None, _pyfree=0):
        if crl is not None:
            self.crl = crl
            self._pyfree = _pyfree
        else:
            self.crl = m2.x509_crl_new()
            self._pyfree = 1

    def __del__(self):
        if self._pyfree:
            m2.x509_crl_free(self.crl)

    def as_text(self):
        """
        Return CRL in PEM format in a string.

        @rtype: string
        @return: String containing the CRL in PEM format.
        """
        buf=BIO.MemoryBuffer()
        m2.x509_crl_print(buf.bio_ptr(), self.crl)
        return buf.read_all()


def load_crl(file):
    """
    Load CRL from file.

    @type file: string
    @param file: Name of file containing CRL in PEM format.

    @rtype: M2Crypto.X509.CRL
    @return: M2Crypto.X509.CRL object.
    """
    f=BIO.openfile(file)
    cptr=m2.x509_crl_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return CRL(cptr, 1)


