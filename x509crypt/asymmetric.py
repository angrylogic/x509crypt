#!/usr/bin/python

"""Wrapper around OpenSSL asymmetric cryptographic operations."""

import ctypes
import atexit
from contextlib import contextmanager

LIBC = ctypes.CDLL("libc.so.6")
LIBSSL = ctypes.CDLL("libssl.so")
try:
    LIBSSL.OPENSSL_add_all_algorithms_conf()
except AttributeError:
    LIBSSL.OPENSSL_add_all_algorithms_noconf()
atexit.register(LIBSSL.EVP_cleanup)

class AsymmetricCryptoError(Exception):
    """Base exception for errors during asymmetric cryptographic operations."""

class AsymmetricContext(object):
    """Wrapper around a EVP_PKEY_CTX. This class should not be
    created directly but rather through the with_certificate and
    with_private_key context managers which handle setup and cleanup of
    the context objects."""

    def __init__(self, context=None):
        self.context = context

    @classmethod
    @contextmanager
    def from_certificate(cls, certificate_path):
        """Load the certificate returning an EVP CTX ready to encrypt.

        :param certificate_path: path to PEM encoded X509 certificate
        :type certificate_path: str
        :returns: AsymmetricContext -- context for encryption/decryption
        """
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
            yield AsymmetricContext(pkey_ctx)
        finally:
            if pkey_ctx is not None:
                LIBSSL.EVP_PKEY_CTX_free(pkey_ctx)
            if pkey is not None:
                LIBSSL.EVP_PKEY_free(pkey)
            if certificate_ctx is not None:
                LIBSSL.X509_free(certificate_ctx)

    @classmethod
    @contextmanager
    def from_private_key(cls, key_path, password=None):
        """Load a private key optionally with password.

        :param key_path: the path to the PEM encoded private key
        :type key_path: str
        :param password: the optional password for the key
        :type password: str
        :returns: AsymmetricContext -- context for encryption/decryption
        """
        pkey = None
        pkey_ctx = None
        password_data = ctypes.c_char_p(password) if password is not None else None
        try:
            key_fp = LIBC.fopen(key_path, "r")
            if not key_fp:
                raise AsymmetricCryptoError("Failed to open private key")
            pkey = LIBSSL.PEM_read_PrivateKey(key_fp, None, None, password_data)
            if not pkey:
                raise AsymmetricCryptoError("Failed reading private key")
            pkey_ctx = LIBSSL.EVP_PKEY_CTX_new(pkey, None)
            if not pkey_ctx:
                raise AsymmetricCryptoError("Failed setting up context from private key")
            yield AsymmetricContext(pkey_ctx)
        finally:
            if pkey_ctx is not None:
                LIBSSL.EVP_PKEY_CTX_free(pkey_ctx)
            if pkey is not None:
                LIBSSL.EVP_PKEY_free(pkey)

    def encrypt(self, data):
        """Encrypt some small data under the asymmetric key."""
        input_buffer = ctypes.c_char_p(data)
        input_buffer_size = ctypes.c_int(len(data))
        if LIBSSL.EVP_PKEY_encrypt_init(self.context) != 1:
            raise AsymmetricCryptoError("Failed initializing encryption")
        output_buffer_size = ctypes.c_int()
        if LIBSSL.EVP_PKEY_encrypt(self.context, None, ctypes.byref(output_buffer_size), None, None) != 1:
            raise AsymmetricCryptoError("Failed during encryption")
        output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
        if LIBSSL.EVP_PKEY_encrypt(self.context, output_buffer, ctypes.byref(output_buffer_size),
                                   input_buffer, input_buffer_size) != 1:
            raise AsymmetricCryptoError("Failed during encryption")
        return ctypes.string_at(output_buffer, size=output_buffer_size.value)

    def decrypt(self, data):
        """Decrypt some small data under the asymmetric key."""
        input_buffer = ctypes.c_char_p(data)
        input_buffer_size = ctypes.c_int(len(data))
        if LIBSSL.EVP_PKEY_decrypt_init(self.context) != 1:
            raise AsymmetricCryptoError("Failed initializing decryption")
        output_buffer_size = ctypes.c_int()
        if LIBSSL.EVP_PKEY_decrypt(self.context, None, ctypes.byref(output_buffer_size), None, None) != 1:
            raise AsymmetricCryptoError("Failed during decryption")
        output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
        if LIBSSL.EVP_PKEY_decrypt(self.context, output_buffer, ctypes.byref(output_buffer_size),
                                   input_buffer, input_buffer_size) != 1:
            raise AsymmetricCryptoError("Failed during decryption")
        return ctypes.string_at(output_buffer, size=output_buffer_size.value)
