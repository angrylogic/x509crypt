#!/usr/bin/python

"""Wrapper around OpenSSL asymmetric cryptographic operations."""

import ctypes
from contextlib import contextmanager

LIBC = ctypes.CDLL("libc.so.6")
LIBSSL = ctypes.CDLL("libssl.so")

class AsymmetricCryptoError(Exception):
    """Base exception for errors during asymmetric cryptographic operations."""

@contextmanager
def certificate(certificate_path):
    """Load the certificate returning an EVP CTX ready to encrypt."""
    pkey = None
    pkey_ctx = None
    certificate_ctx = None
    try:
        certificate_fp = LIBC.fopen(certificate_path, "r")
        if not certificate_fp:
            raise AsymmetricCryptoError("Failed to open X509 certificate")
        certificate_ctx = LIBSSL.PEM_read_X509(certificate_fp, None, None, None)
        if not certificate_ctx:
            raise AsymmetricCryptoError("Failed reading X509 certificate")
        pkey = LIBSSL.X509_get_pubkey(certificate_ctx)
        if not pkey:
            raise AsymmetricCryptoError("Failed extracting public key from certificate")
        pkey_ctx = LIBSSL.EVP_PKEY_CTX_new(pkey, None)
        if not pkey_ctx:
            raise AsymmetricCryptoError("Failed setting up context from public key")
        yield pkey_ctx
    finally:
        if pkey_ctx is not None:
            LIBSSL.EVP_PKEY_CTX_free(pkey_ctx)
        if pkey is not None:
            LIBSSL.EVP_PKEY_free(pkey)
        if certificate_ctx is not None:
            LIBSSL.X509_free(certificate_ctx)

@contextmanager
def private_key(key_path):
    """Load a private key returnign an EVP CTX ready to decrypt."""
    pkey = None
    pkey_ctx = None
    try:
        key_fp = LIBC.fopen(key_path, "r")
        if not key_fp:
            raise AsymmetricCryptoError("Failed to open private key")
        pkey = LIBSSL.PEM_read_PrivateKey(key_fp, None, None, None)
        if not pkey:
            raise AsymmetricCryptoError("Failed reading private key")
        pkey_ctx = LIBSSL.EVP_PKEY_CTX_new(pkey, None)
        if not pkey_ctx:
            raise AsymmetricCryptoError("Failed setting up context from private key")
        yield pkey_ctx
    finally:
        if pkey_ctx is not None:
            LIBSSL.EVP_PKEY_CTX_free(pkey_ctx)
        if pkey is not None:
            LIBSSL.EVP_PKEY_free(pkey)

def encrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    if LIBSSL.EVP_PKEY_encrypt_init(pkey_ctx) != 1:
        raise AsymmetricCryptoError("Failed initializing encryption")
    output_buffer_size = ctypes.c_int()
    if LIBSSL.EVP_PKEY_encrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) != 1:
        raise AsymmetricCryptoError("Failed during encryption")
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    if LIBSSL.EVP_PKEY_encrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size),
                               input_buffer, input_buffer_size) != 1:
        raise AsymmetricCryptoError("Failed during encryption")
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)

def decrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    if LIBSSL.EVP_PKEY_decrypt_init(pkey_ctx) != 1:
        raise AsymmetricCryptoError("Failed initializing decryption")
    output_buffer_size = ctypes.c_int()
    if LIBSSL.EVP_PKEY_decrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) != 1:
        raise AsymmetricCryptoError("Failed during decryption")
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    if LIBSSL.EVP_PKEY_decrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size),
                               input_buffer, input_buffer_size) != 1:
        raise AsymmetricCryptoError("Failed during decryption")
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)
