"""M2Crypto wrapper for OpenSSL X509 API.

Copyright (c) 1999 Ng Pheng Siong. All rights reserved. """

RCS_id='$Id: X509.py,v 1.2 1999/12/22 15:53:58 ngps Exp $'

import BIO
import M2Crypto 
m2=M2Crypto

m2.x509_init()

class X509_Store_Context:
    def __init__(self, x509_store_ctx, thisown=0):
        self.ctx=x509_store_ctx
        self.thisown=thisown


class X509:
	def __init__(self, x509):
		self.x509=x509

	def as_text(self):
		buf=BIO.MemoryBuffer()
		m2.x509_print(buf.bio_ptr(), self.x509)
		return buf.read_all()

	def as_der(self):
		buf=BIO.MemoryBuffer()
		m2.i2d_x509(buf.bio_ptr(), self.x509)
		return buf.read_all()


def load_cert(pemfile):
    f=BIO.openfile(pemfile)
    cptr=m2.x509_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return X509(cptr)


class X509_Stack:
	def __init__(self, stack):
		self.stack=stack

	def __len__(self):
		return m2.sk_x509_num(self.stack)

	def __getitem__(self, idx):
		if idx < 0 or idx >= m2.sk_x509_num(self.stack):
			raise IndexError, 'index out of range'
		v=m2.sk_x509_value(self.stack, idx)
		return X509(v)


class Request:
    def __init__(self, req):
        self.req = req

	def as_text(self):
		buf=BIO.MemoryBuffer()
		m2.x509_req_print(buf.bio_ptr(), self.req)
		return buf.read_all()


def load_request(pemfile):
    f=BIO.openfile(pemfile)
    cptr=m2.x509_req_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return Request(cptr)


class CRL:
    def __init__(self, crl):
        self.crl = crl

	def as_text(self):
		buf=BIO.MemoryBuffer()
		m2.x509_crl_print(buf.bio_ptr(), self.crl)
		return buf.read_all()


def load_crl(pemfile):
    f=BIO.openfile(pemfile)
    cptr=m2.x509_crl_read_pem(f.bio_ptr())
    f.close()
    if cptr is None:
        raise Err.get_error()
    return CRL(cptr)


v_ok=m2.X509_V_OK
v_err_unable_to_get_issuer_cert=m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
v_err_unable_to_get_crl=m2.X509_V_ERR_UNABLE_TO_GET_CRL
v_err_unable_to_decrypt_cert_sig=m2.X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
v_err_unable_to_decrypt_crl_sig=m2.X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
v_err_unable_to_decode_issuer_pubkey=m2.X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
v_err_cert_sig_failure=m2.X509_V_ERR_CERT_SIGNATURE_FAILURE
v_err_crl_sig_failure=m2.X509_V_ERR_CRL_SIGNATURE_FAILURE
v_err_cert_not_yet_valid=m2.X509_V_ERR_CERT_NOT_YET_VALID
v_err_cert_has_expired=m2.X509_V_ERR_CERT_HAS_EXPIRED
v_err_crl_not_yet_valid=m2.X509_V_ERR_CRL_NOT_YET_VALID
v_err_crl_has_expired=m2.X509_V_ERR_CRL_HAS_EXPIRED
v_err_in_cert_not_before_field=m2.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
v_err_in_cert_not_after_field=m2.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
v_err_in_crl_last_update_field=m2.X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
v_err_in_crl_next_update_field=m2.X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
v_err_out_of_mem=m2.X509_V_ERR_OUT_OF_MEM
v_err_depth_zero_self_signed_cert=m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
v_err_self_signed_cert_in_chain=m2.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
v_err_unable_to_get_issuer_cert_locally=m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
v_err_unable_to_verify_leaf_sig=m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
v_err_cert_chain_too_long=m2.X509_V_ERR_CERT_CHAIN_TOO_LONG
v_err_cert_revoked=m2.X509_V_ERR_CERT_REVOKED
v_err_app_rejected=m2.X509_V_ERR_APPLICATION_VERIFICATION

X509_verify_result={\
    v_ok: 'ok',\
    v_err_unable_to_get_issuer_cert: 'unable to get issuer cert',\
    v_err_unable_to_get_crl: 'unable to get crl',\
    v_err_unable_to_decrypt_cert_sig: 'unable to decrypt cert sig',\
    v_err_unable_to_decrypt_crl_sig: 'unable to decrypt crl sig',\
    v_err_unable_to_decode_issuer_pubkey: 'unable to decode issuer pubkey',\
    v_err_cert_sig_failure: 'cert sig failure',\
    v_err_crl_sig_failure: 'crl sig failure',\
    v_err_cert_not_yet_valid: 'cert not yet valid',\
	v_err_cert_has_expired: 'cert has expired',\
	v_err_crl_not_yet_valid: 'crl not yet valid',\
	v_err_crl_has_expired: 'crl has expired',\
	v_err_in_cert_not_before_field: 'error in cert not before field',\
	v_err_in_cert_not_after_field: 'error in cert not after field',\
	v_err_in_crl_last_update_field: 'error in crl last update field',\
	v_err_in_crl_next_update_field: 'error in crl next update field',\
	v_err_out_of_mem: 'out of memory',\
	v_err_depth_zero_self_signed_cert: 'depth zero self-signed cert',\
	v_err_self_signed_cert_in_chain: 'self-signed cert in cert chain',\
	v_err_unable_to_get_issuer_cert_locally: 'unable to get issuer cert locally',\
	v_err_unable_to_verify_leaf_sig: 'unable to verify leaf sig',\
	v_err_cert_chain_too_long: 'cert chain too long',\
	v_err_cert_revoked: 'cert revoked',\
	v_err_app_rejected: 'cert rejected by application'\
    }



