"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: Context.py,v 1.3 2000/08/23 15:35:24 ngps Exp $'

# M2Crypto
import cb
from M2Crypto import util, BIO, Err, m2

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
    def __init__(self, protocol='sslv23'):
        proto = getattr(m2, protocol + '_method')
        if proto is None:
            raise ValueError, "no such protocol '%s'" % protocol
        self.ctx = m2.ssl_ctx_new(proto())
        self.allow_unknown_ca = 0
        map()[self.ctx] = self

    def __del__(self):
        del map()[self.ctx]
        m2.ssl_ctx_free(self.ctx)

    def load_cert(self, certfile, keyfile=None, callback=util.passphrase_callback):
        m2.ssl_ctx_passphrase_callback(self.ctx, callback)
        m2.ssl_ctx_use_cert(self.ctx, certfile)
        if not keyfile: 
            keyfile = certfile
        m2.ssl_ctx_use_privkey(self.ctx, keyfile)
        if not m2.ssl_ctx_check_privkey(self.ctx):
            raise ValueError, 'public/private key mismatch'

    def load_client_ca(self, cafile):
        m2.ssl_ctx_load_client_CA(self.ctx, cafile)

    load_client_CA = load_client_ca

    def load_verify_info(self, cafile):
        return m2.ssl_ctx_load_verify_locations(self.ctx, cafile)

    load_verify_location = load_verify_info

    def set_session_id_ctx(self, id):
        ret = m2.ssl_ctx_set_session_id_context(self.ctx, id)
        if not ret:
            raise Err.SSLError(Err.get_error_code(), '')

    def set_allow_unknown_ca(self, ok):
        self.allow_unknown_ca = ok

    def get_allow_unknown_ca(self):
        return self.allow_unknown_ca

    def set_verify(self, mode, depth, callback=cb.ssl_verify_callback):
        m2.ssl_ctx_set_verify(self.ctx, mode, callback)
        m2.ssl_ctx_set_verify_depth(self.ctx, depth)

    def get_verify_mode(self):
        return m2.ssl_ctx_get_verify_mode(self.ctx)

    def get_verify_depth(self):
        return m2.ssl_ctx_get_verify_depth(self.ctx)

    def set_tmp_dh(self, dhpfile):
        f = BIO.openfile(dhpfile)
        dhp = m2.dh_read_parameters(f.bio_ptr())
        m2.ssl_ctx_set_tmp_dh(self.ctx, dhp)

    def set_info_callback(self, callback=cb.ssl_info_callback):
        m2.ssl_ctx_set_info_callback(self.ctx, callback) 

    def set_cipher_list(self, cipher_list):
        return m2.ssl_ctx_set_cipher_list(self.ctx, cipher_list)

    def add_session(self, session):
        return m2.ssl_ctx_add_session(self.ctx, session._ptr())

    def remove_session(self, session):
        return m2.ssl_ctx_remove_session(self.ctx, session._ptr())

