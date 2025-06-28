#!/usr/bin/env python

"""Test file for M2Crypto.Provider."""

import hashlib
import os

from M2Crypto import Provider

CERT = 'pkcs11:id=%01;type=cert'
PRIVKEY = 'pkcs11:id=%01;type=private'
PUBKEY = 'pkcs11:id=%01;type=public'

p = Provider.Provider('pkcs11')
cert = p.load_certificate(CERT)
privkey = p.load_key(PRIVKEY)
pubkey = p.load_key(PUBKEY)

print('Certificate :')
cert_pem_bytes = cert.as_pem()
print(cert_pem_bytes.decode('utf-8'))
print(cert.as_text())

cert_pubkey = cert.get_pubkey()
assert (cert_pubkey.as_der() == pubkey.as_der()), f"Public key DER comparison failed : {cert_pubkey.as_der()} != {pubkey.as_der()}"
print(f"Public key DER : {cert_pubkey.as_der().hex()}\n")

assert (cert_pubkey.get_modulus() == pubkey.get_modulus()), f"Modulus comparison failed : {cert_pubkey.get_modulus()} != {pubkey.get_modulus()}"
modulus = cert_pubkey.get_modulus()
modulus = bytes.fromhex(modulus.decode('utf-8'))
print(f"Modulus : {modulus.hex()}\n")

random_data = os.urandom(32)
print(f"Random data : {random_data.hex()}\n")

hashed_data = hashlib.sha256(random_data).digest()
print(f"SHA256 : {hashed_data.hex()}\n")

privkey.sign_init()
privkey.sign_update(hashed_data)
signature = privkey.sign_final()
print(f"Signature with private key : {signature.hex()}\n")

pubkey.verify_init()
pubkey.verify_update(hashed_data)
verified = pubkey.verify_final(signature)
print(f"Verification with public key : {'OK' if verified == 1 else 'NOK'} (verified={verified})\n")
