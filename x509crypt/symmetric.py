#!/usr/bin/python

import ctypes
import atexit
import sys
import tempfile
from x509crypt.encoder import TAG_SIZE

# GCM control constants from evp.h
EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11

LIBC = ctypes.CDLL("libc.so.6")
LIBSSL = ctypes.CDLL("libssl.so")
try:
    LIBSSL.OPENSSL_add_all_algorithms_conf()
except AttributeError:
    LIBSSL.OPENSSL_add_all_algorithms_noconf()
atexit.register(LIBSSL.EVP_cleanup)

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
    def __init__(self, message):
        error_capture = tempfile.TemporaryFile()
        LIBSSL.ERR_print_errors_fp(LIBC.fdopen(error_capture.fileno(), "w"))
        error_capture.flush()
        error_capture.seek(0)
        message = message + ": " + error_capture.read()
        Exception.__init__(self, message)

def encrypt(symmetric_iv, symmetric_key, fp_in, fp_out):
    evp_cipher_ctx = EvpCipherCtx()
    LIBSSL.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = LIBSSL.EVP_EncryptInit_ex(ctypes.byref(evp_cipher_ctx),
                                    LIBSSL.EVP_aes_256_gcm(),
                                    None, None, None)
    if ret <= 0:
        raise SymmetricCryptoError("Failed initializing encryption")

    ret = LIBSSL.EVP_CIPHER_CTX_ctrl(ctypes.byref(evp_cipher_ctx),
                                     EVP_CTRL_GCM_SET_IVLEN,
                                     len(symmetric_iv), None)
    if ret <= 0:
        raise SymmetricCryptoError("Failed initializing encryption")

    ret = LIBSSL.EVP_EncryptInit_ex(ctypes.byref(evp_cipher_ctx), None, None,
                                    ctypes.c_char_p(symmetric_key),
                                    ctypes.c_char_p(symmetric_iv))
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

    tag_buffer = ctypes.create_string_buffer(TAG_SIZE)
    ret = LIBSSL.EVP_CIPHER_CTX_ctrl(ctypes.byref(evp_cipher_ctx), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag_buffer)
    if ret <= 0:
        raise SymmetricCryptoError("Failed during encryption authentication setup")

    return tag_buffer.value

def decrypt(symmetric_iv, symmetric_key, authentication_tag, fp_in, fp_out):
    evp_cipher_ctx = EvpCipherCtx()
    LIBSSL.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = LIBSSL.EVP_DecryptInit_ex(ctypes.byref(evp_cipher_ctx),
                                    LIBSSL.EVP_aes_256_gcm(),
                                    None, None, None)
    if ret <= 0:
        raise SymmetricCryptoError("Failed initializing cipher for decryption")

    ret = LIBSSL.EVP_CIPHER_CTX_ctrl(ctypes.byref(evp_cipher_ctx),
                                     EVP_CTRL_GCM_SET_IVLEN,
                                     len(symmetric_iv), None)
    if ret <= 0:
        raise SymmetricCryptoError("Failed setting IV size for decryption")

    ret = LIBSSL.EVP_DecryptInit_ex(ctypes.byref(evp_cipher_ctx), None, None,
                                    ctypes.c_char_p(symmetric_key),
                                    ctypes.c_char_p(symmetric_iv))
    if ret <= 0:
        raise SymmetricCryptoError("Failed setting IV and encryption key for decryption")

    out_buf = ctypes.create_string_buffer(4096+32)
    for encryption_round, in_buf in enumerate(iter(lambda: fp_in.read(4096), "")):
        out_sz = ctypes.c_int(4096+32) # reset after update in previous iteration
        ret = LIBSSL.EVP_DecryptUpdate(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz),
                                       ctypes.c_char_p(in_buf), ctypes.c_int(len(in_buf)))
        if ret <= 0:
            #raise SymmetricCryptoError("Failed during decryption update on round %d" % encryption_round)
            pass
        fp_out.write(out_buf[:out_sz.value])

    # Verify authentication tag from the encryption process
    ret = LIBSSL.EVP_CIPHER_CTX.ctrl(ctypes.byref(evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG,
                                                  TAG_SIZE, authentication_tag))
    if ret <= 0:
        raise SymmetricCryptoError("Failed during decryption authentication setup")

    ret = LIBSSL.EVP_DecryptFinal(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz))
    if ret <= 0:
        raise SymmetricCryptoError("Faield during decryption finalization")
    fp_out.write(out_buf[:out_sz.value])
