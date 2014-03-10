#!/usr/bin/python

import ctypes
from contextlib import contextmanager

libc = ctypes.CDLL("libc.so.6")
openssl = ctypes.CDLL("libssl.so")

@contextmanager
def certificate(certificate_path):
    """Load the certificate returning an EVP CTX ready to encrypt."""
    try:
        certificate_fp = libc.fopen("test.pem", "r")
        certificate = openssl.PEM_read_X509(certificate_fp, None, None, None)
        assert certificate
        pkey = openssl.X509_get_pubkey(certificate)
        assert pkey
        pkey_ctx = openssl.EVP_PKEY_CTX_new(pkey, None)
        assert pkey_ctx
        yield pkey_ctx
    finally:
        openssl.EVP_PKEY_CTX_free(pkey_ctx)
        openssl.EVP_PKEY_free(pkey)
        openssl.X509_free(certificate)

@contextmanager
def private_key(key_path):
    try:
        key_fp = libc.fopen("test.key", "r")
        pkey = openssl.PEM_read_PrivateKey(key_fp, None, None, None)
        assert pkey
        pkey_ctx = openssl.EVP_PKEY_CTX_new(pkey, None)
        assert pkey_ctx
        yield pkey_ctx
    finally:
        openssl.EVP_PKEY_CTX_free(pkey_ctx)
        openssl.EVP_PKEY_free(pkey)

def encrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    assert openssl.EVP_PKEY_encrypt_init(pkey_ctx) == 1
    output_buffer_size = ctypes.c_int()
    assert openssl.EVP_PKEY_encrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) == 1
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    assert openssl.EVP_PKEY_encrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size), 
                                              input_buffer, input_buffer_size) == 1
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)

def decrypt(pkey_ctx, data):
    """Encrypt some small data under the asymmetric key."""
    input_buffer = ctypes.c_char_p(data)
    input_buffer_size = ctypes.c_int(len(data))
    assert openssl.EVP_PKEY_decrypt_init(pkey_ctx) == 1
    output_buffer_size = ctypes.c_int()
    assert openssl.EVP_PKEY_decrypt(pkey_ctx, None, ctypes.byref(output_buffer_size), None, None) == 1
    output_buffer = (ctypes.c_char_p * output_buffer_size.value)()
    assert openssl.EVP_PKEY_decrypt(pkey_ctx, output_buffer, ctypes.byref(output_buffer_size), 
                                              input_buffer, input_buffer_size) == 1
    return ctypes.string_at(output_buffer, size=output_buffer_size.value)

if __name__ == "__main__":
    with certificate("test.pem") as pkey_ctx:
        e_content = encrypt(pkey_ctx, "tehe")
        print e_content.encode("base64")
    with private_key("test.pem") as pkey_ctx:
        d_content = decrypt(pkey_ctx, e_content)
        print d_content
