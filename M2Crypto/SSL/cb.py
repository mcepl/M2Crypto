"""Copyright (c) 1999-2000 Ng Pheng Siong. All rights reserved."""

RCS_id='$Id: cb.py,v 1.3 2000/08/23 15:36:29 ngps Exp $'

# Python
import sys

# M2Crypto
import Connection, Context
from M2Crypto import X509, m2

def ssl_verify_callback_stub(ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok):
    return ok


def ssl_verify_callback(ssl_ctx_ptr, x509_ptr, errnum, errdepth, ok):
    unknown_issuer = [
        m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        m2.X509_V_ERR_CERT_UNTRUSTED
        ]
    ssl_ctx = Context.map()[ssl_ctx_ptr]
    if errnum in unknown_issuer: 
        if ssl_ctx.get_allow_unknown_ca():
            sys.stderr.write("policy: %s: permitted...\n" % (m2.x509_get_verify_error(errnum)))
            sys.stderr.flush()
            ok = 1
    # CRL checking goes here...
    if ok:
        if ssl_ctx.get_verify_depth() >= errdepth:
            ok = 1
        else:
            ok = 0
    return ok


# Cribbed from OpenSSL's apps/s_cb.c.
def ssl_info_callback0(where, ret, ssl_ptr):
    ssl_conn = Connection.map()[ssl_ptr]
    sys.stdout.write(ssl_ptr + ':' + str(sys.getrefcount(ssl_conn)) + '\n')
    sys.stdout.flush()


def ssl_info_callback(where, ret, ssl_ptr):

    #ssl_conn = Connection.map()[ssl_ptr]
    #sys.stdout.write(ssl_ptr + ':' + str(sys.getrefcount(ssl_conn)) + '\n')
    #sys.stdout.flush()

    w = where & ~m2.SSL_ST_MASK
    if (w & m2.SSL_ST_CONNECT):
        state = "SSL connect"
    elif (w & m2.SSL_ST_ACCEPT):
        state = "SSL accept"
    else:
        state = "SSL state unknown"

    if (where & m2.SSL_CB_LOOP):
        sys.stderr.write("LOOP: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
        sys.stderr.flush()
        return

    if (where & m2.SSL_CB_EXIT):
        if not ret:
            sys.stderr.write("FAILED: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
            sys.stderr.flush()
        else:
            sys.stderr.write("INFO: %s: %s\n" % (state, m2.ssl_get_state_v(ssl_ptr)))
            sys.stderr.flush()
        return

    if (where & m2.SSL_CB_ALERT):
        #ssl_conn = Connection.map()[ssl_ptr]
        if (where & m2.SSL_CB_READ):
            w = 'read'
        #   ssl_attr = ssl_conn._read_closed
        else:
            w = 'write'
        #   ssl_attr = ssl_conn._write_closed
        sys.stderr.write("ALERT: %s: %s: %s\n" % \
            (w, m2.ssl_get_alert_type_v(ret), m2.ssl_get_alert_desc_v(ret)))
        sys.stderr.flush()
        #if m2.ssl_get_alert_desc(ret) == SSL_AD_CLOSE_NOTIFY:
        #    ssl_attr = 1
        #if ssl_conn._read_closed and ssl_conn._write_closed:
        #    sys.stderr.write("Deleting " + ssl_ptr + '\n')
        #    sys.stderr.flush()
        #    del Connection.map()[ssl_ptr]
        return


