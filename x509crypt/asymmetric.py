#!/usr/bin/python

import ctypes
from contextlib import contextmanager

libc = ctypes.CDLL("libc.so.6")
openssl = ctypes.CDLL("libssl.so")

class AsymmetricCryptoError(Exception):
    """Base exception class for errors from the crypto library."""
    pass

@contextmanager
def certificate(certificate_path):
    """Load the certificate returning an EVP CTX ready to encrypt."""
    pkey_ctx = None
    pkey = None
    certificate = None
    try:
        certificate_fp = libc.fopen(certificate_path, "r")
        certificate = openssl.PEM_read_X509(certificate_fp, None, None, None)
        if not certificate:
            raise AsymmetricCryptoError("Failed reading X509 certificate")
        pkey = openssl.X509_get_pubkey(certificate)
        if not pkey:
            raise AsymmetricCryptoError("Failed extracting public key from certificate")
        pkey_ctx = openssl.EVP_PKEY_CTX_new(pkey, None)
        if not pkey_ctx:
            raise AsymmetricCryptoError("Failed setting up context from public key")
        yield pkey_ctx
    finally:
        if pkey_ctx is not None:
            openssl.EVP_PKEY_CTX_free(pkey_ctx)
        if pkey is not None:
            openssl.EVP_PKEY_free(pkey)
        if certificate is not None:
            openssl.X509_free(certificate)

@contextmanager
def private_key(key_path):
    pkey_ctx = None
    pkey = None
    try:
        key_fp = libc.fopen(key_path, "r")
        pkey = openssl.PEM_read_PrivateKey(key_fp, None, None, None)
        if not pkey:
            raise AsymmetricCryptoError("Failed reading private key")
        pkey_ctx = openssl.EVP_PKEY_CTX_new(pkey, None)
        if not pkey_ctx:
            raise AsymmetricCryptoError("Failed setting up context from private key")
        yield pkey_ctx
    finally:
        if pkey_ctx is not None:
            openssl.EVP_PKEY_CTX_free(pkey_ctx)
        if pkey is not None:
            openssl.EVP_PKEY_free(pkey)

def encrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    if openssl.EVP_PKEY_encrypt_init(pkey_ctx) != 1:
        raise AsymmetricCryptoError("Failed initializing encryption")
    output_buffer_size = ctypes.c_int()
    if openssl.EVP_PKEY_encrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) != 1:
        raise AsymmetricCryptoError("Failed during encryption")
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    if openssl.EVP_PKEY_encrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size),
                                input_buffer, input_buffer_size) != 1:
        raise AsymmetricCryptoError("Failed during encryption")
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)

def decrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    if openssl.EVP_PKEY_decrypt_init(pkey_ctx) != 1:
        raise AsymmetricCryptoError("Failed initializing decryption")
    output_buffer_size = ctypes.c_int()
    if openssl.EVP_PKEY_decrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) != 1:
        raise AsymmetricCryptoError("Failed during decryption")
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    if openssl.EVP_PKEY_decrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size),
                                input_buffer, input_buffer_size) != 1:
        raise AsymmetricCryptoError("Failed during decryption")
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)

if __name__ == "__main__":
    with certificate("test.pem") as pkey_ctx:
        e_content = encrypt(pkey_ctx, "tehe")
        print e_content.encode("base64")
    with private_key("test.pem") as pkey_ctx:
        d_content = decrypt(pkey_ctx, e_content)
        print d_content
