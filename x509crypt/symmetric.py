#!/usr/bin/python

import ctypes
import atexit

LIBSSL = ctypes.CDLL("libssl.so")
try:
    LIBSSL.OPENSSL_add_all_algorithms_conf()
except AttributeError:
    LIBSSL.OPENSSL_add_all_algorithms_noconf()
atexit.register(lambda: LIBSSL.EVP_cleanup())

class EvpCipherCtx(ctypes.Structure):
    _fields_ = [("cipher", ctypes.c_void_p),
                ("engine", ctypes.c_void_p),
                ("encrypt", ctypes.c_int),
                ("buf_len", ctypes.c_int),
                ("oiv", ctypes.c_char * 16),
                ("iv", ctypes.c_char * 16),
                ("buf", ctypes.c_char * 32),
                ("num", ctypes.c_int),
                ("app_data", ctypes.c_void_p),
                ("key_len", ctypes.c_int),
                ("flags", ctypes.c_long),
                ("cipher_data", ctypes.c_void_p),
                ("final_used", ctypes.c_int),
                ("block_mask", ctypes.c_int),
                ("final", ctypes.c_char * 32)]

class SymmetricCryptoError(Exception):
    """Base exception for errors during symmetric cryptographic operations."""

def encrypt(symmetric_iv, symmetric_key, fp_in, fp_out):
    evp_cipher_ctx = EvpCipherCtx()
    LIBSSL.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = LIBSSL.EVP_EncryptInit(ctypes.byref(evp_cipher_ctx), LIBSSL.EVP_aes_256_ctr(),
                                 ctypes.c_char_p(symmetric_key), ctypes.c_char_p(symmetric_iv))
    if ret <= 0:
        raise SymmetricCryptoError("Failed initializing encryption")
    out_buf = ctypes.create_string_buffer(4096+32)
    out_sz = ctypes.c_int(4096+32)
    for in_buf in iter(lambda: fp_in.read(4096), ""):
        ret = LIBSSL.EVP_EncryptUpdate(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz),
                                       ctypes.c_char_p(in_buf), ctypes.c_int(len(in_buf)))
        if ret <= 0:
            raise SymmetricCryptoError("Failed during encryption update")
        fp_out.write(out_buf[:out_sz.value])
    ret = LIBSSL.EVP_EncryptFinal(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz))
    if ret <= 0:
        raise SymmetricCryptoError("Failed during encryption finalization")
    fp_out.write(out_buf[:out_sz.value])

def decrypt(symmetric_iv, symmetric_key, fp_in, fp_out):
    evp_cipher_ctx = EvpCipherCtx()
    LIBSSL.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = LIBSSL.EVP_DecryptInit(ctypes.byref(evp_cipher_ctx), LIBSSL.EVP_aes_256_ctr(),
                                 ctypes.c_char_p(symmetric_key), ctypes.c_char_p(symmetric_iv))
    if ret <= 0:
        raise SymmetricCryptoError("Failed initializing decryption")
    out_buf = ctypes.create_string_buffer(4096+32)
    out_sz = ctypes.c_int(4096+32)
    for in_buf in iter(lambda: fp_in.read(4096), ""):
        ret = LIBSSL.EVP_DecryptUpdate(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz),
                                       ctypes.c_char_p(in_buf), ctypes.c_int(len(in_buf)))
        if ret <= 0:
            raise SymmetricCryptoError("Failed during decryption update")
        fp_out.write(out_buf[:out_sz.value])
    ret = LIBSSL.EVP_DecryptFinal(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz))
    if ret <= 0:
        raise SymmetricCryptoError("Faield during decryption finalization")
    fp_out.write(out_buf[:out_sz.value])
