"""M2Crypto.SSL.Context

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id$'

# M2Crypto
import cb
from M2Crypto import util, BIO, Err, RSA, m2, X509

class _ctxmap:
    singleton = None
    def __init__(self):
        self.map = {}

    def __getitem__(self, key):
        return self.map[key] 

    def __setitem__(self, key, value):
        self.map[key] = value

    def __delitem__(self, key):
        del self.map[key]

def map():
    if _ctxmap.singleton is None:
        _ctxmap.singleton = _ctxmap()
    return _ctxmap.singleton


class Context:

    """'Context' for SSL connections."""

    def __init__(self, protocol='sslv23', weak_crypto=None):
        proto = getattr(m2, protocol + '_method')
        if proto is None:
            raise ValueError, "no such protocol '%s'" % protocol
        self.ctx = m2.ssl_ctx_new(proto())
        self.allow_unknown_ca = 0
        map()[self.ctx] = self
        m2.ssl_ctx_set_cache_size(self.ctx, 128L)
        if weak_crypto is None:
            if protocol == 'sslv23':
                self.set_options(m2.SSL_OP_ALL | m2.SSL_OP_NO_SSLv2)
            self.set_cipher_list('ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH')

    def __del__(self):
        m2.ssl_ctx_free(self.ctx)

    def close(self):
        del map()[self.ctx]
        
    def load_cert(self, certfile, keyfile=None, callback=util.passphrase_callback):
        """Load certificate and private key into the context.
        
        'certfile'  - File object containing the PEM-encoded certificate.

        'keyfile'   - File object containing the PEM-encoded private key.
        Default value of None indicates that the private key is to be found
        in 'certfile'.

        'callback'  - Callable object to be invoked if the private key is
        passphrase-protected. Default callback provides a simple
        terminal-style input for the passphrase.
        """
        m2.ssl_ctx_passphrase_callback(self.ctx, callback)
        m2.ssl_ctx_use_cert(self.ctx, certfile)
        if not keyfile: 
            keyfile = certfile
        m2.ssl_ctx_use_privkey(self.ctx, keyfile)
        if not m2.ssl_ctx_check_privkey(self.ctx):
            raise ValueError, 'public/private key mismatch'

    def load_cert_chain(self, certchainfile, keyfile=None, callback=util.passphrase_callback):
        """Load certificate chain and private key into the context.
        
        'certchainfile' - File object containing the PEM-encoded certificate chain.

        'keyfile'       - File object containing the PEM-encoded private key.
        Default value of None indicates that the private key is to be found
        in 'certchainfile'.

        'callback'      - Callable object to be invoked if the private key is
        passphrase-protected. Default callback provides a simple
        terminal-style input for the passphrase.
        """
        m2.ssl_ctx_passphrase_callback(self.ctx, callback)
        m2.ssl_ctx_use_cert_chain(self.ctx, certchainfile)
        if not keyfile: 
            keyfile = certchainfile
        m2.ssl_ctx_use_privkey(self.ctx, keyfile)
        if not m2.ssl_ctx_check_privkey(self.ctx):
            raise ValueError, 'public/private key mismatch'

    def set_client_CA_list_from_file(self, cafile):
        """Load CA certs into the context. These CA certs are sent to the
        peer during *SSLv3 certificate request*.
        
        'cafile'    - File object containing one or more PEM-encoded CA
        certificates concatenated together.
        """
        m2.ssl_ctx_set_client_CA_list_from_file(self.ctx, cafile)

    # Deprecated.
    load_client_CA = load_client_ca = set_client_CA_list_from_file

    def load_verify_locations(self, cafile=None, capath=None):
        """Load CA certs into the context. These CA certs are used during
        verification of the peer's certificate.

        'cafile'    - File containing one or more PEM-encoded CA
        certificates concatenated together.
        'capath'    - Directory containing PEM-encoded CA certificates
        (one certificate per file).
        """
        assert not (cafile is None and capath is None), "cafile and capath are None."
        return m2.ssl_ctx_load_verify_locations(self.ctx, cafile, capath)

    # Deprecated.
    load_verify_info = load_verify_locations

    def set_session_id_ctx(self, id):
        ret = m2.ssl_ctx_set_session_id_context(self.ctx, id)
        if not ret:
            raise Err.SSLError(Err.get_error_code(), '')

    def set_allow_unknown_ca(self, ok): 
        """Set the context to accept/reject a peer certificate if the 
        certificate's CA is unknown.

        'ok'        - 'true' to accept, 'false' to reject.
        """
        self.allow_unknown_ca = ok

    def get_allow_unknown_ca(self):
        """Get the context's setting that accepts/rejects a peer
        certificate if the certificate's CA is unknown.
        """
        return self.allow_unknown_ca

    #def set_verify(self, mode, depth, callback=cb.ssl_verify_callback):
    def set_verify(self, mode, depth, callback=None):
        if callback is None:
            m2.ssl_ctx_set_verify_default(self.ctx, mode)
        else:
            m2.ssl_ctx_set_verify(self.ctx, mode, callback)
        m2.ssl_ctx_set_verify_depth(self.ctx, depth)

    def get_verify_mode(self):
        return m2.ssl_ctx_get_verify_mode(self.ctx)

    def get_verify_depth(self):
        return m2.ssl_ctx_get_verify_depth(self.ctx)

    def set_tmp_dh(self, dhpfile):
        """Load ephemeral DH parameters into the context.

        'dhpfile'   - File object containing the PEM-encoded DH 
        parameters.
        """
        f = BIO.openfile(dhpfile)
        dhp = m2.dh_read_parameters(f.bio_ptr())
        m2.ssl_ctx_set_tmp_dh(self.ctx, dhp)

    def set_tmp_dh_callback(self, callback=None):
        if callback is not None:
            m2.ssl_ctx_set_tmp_dh_callback(self.ctx, callback) 

    def set_tmp_rsa(self, rsa):
        """Load ephemeral RSA key into the context.

        'rsa'   - M2Crypto.RSA.RSA instance.
        """
        if isinstance(rsa, RSA.RSA):
            m2.ssl_ctx_set_tmp_rsa(self.ctx, rsa.rsa)
        else:
            raise TypeError, "Expected an instance of RSA.RSA, got %s." % (rsa,)

    def set_tmp_rsa_callback(self, callback=None):
        if callback is not None:
            m2.ssl_ctx_set_tmp_rsa_callback(self.ctx, callback) 

    def set_info_callback(self, callback=cb.ssl_info_callback):
        """
        Set a callback function that can be used to get state information
        about the SSL connections that are created from this context.
        
        @param callback: Callback function. The default prints information to
                         stderr.
        """
        m2.ssl_ctx_set_info_callback(self.ctx, callback) 

    def set_cipher_list(self, cipher_list):
        return m2.ssl_ctx_set_cipher_list(self.ctx, cipher_list)

    def add_session(self, session):
        return m2.ssl_ctx_add_session(self.ctx, session._ptr())

    def remove_session(self, session):
        return m2.ssl_ctx_remove_session(self.ctx, session._ptr())

    def get_session_timeout(self):
        return m2.ssl_ctx_get_session_timeout(self.ctx)

    def set_session_timeout(self, timeout):
        return m2.ssl_ctx_set_session_timeout(self.ctx, timeout)

    def set_session_cache_mode(self, mode):
        return m2.ssl_ctx_set_session_cache_mode(self.ctx, mode)

    def get_session_cache_mode(self):
        return m2.ssl_ctx_get_session_cache_mode(self.ctx)

    def set_options(self, op):
        return m2.ssl_ctx_set_options(self.ctx, op)

    def get_cert_store(self):
        """
        Get the certificate store associated with this context.
        
        @warning: The store is NOT refcounted, and as such can not be relied
        to be valid once the context goes away or is changed.
        """
        return X509.X509_Store(m2.ssl_ctx_get_cert_store(self.ctx))
    
