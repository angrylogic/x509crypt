#!/usr/bin/python

import ctypes
from contextlib import contextmanager

libc = ctypes.CDLL("libc.so.6")
openssl = ctypes.CDLL("libssl.so")

class EVP_CIPHER_CTX(ctypes.Structure):
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


def encrypt(symmetric_iv, symmetric_key, fp_in, fp_out):
    evp_cipher_ctx = EVP_CIPHER_CTX()
    openssl.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = openssl.EVP_EncryptInit(ctypes.byref(evp_cipher_ctx), openssl.EVP_aes_256_ctr(),
                                  ctypes.c_char_p(symmetric_key), ctypes.c_char_p(symmetric_iv))
    assert ret > 0
    out_buf = ctypes.create_string_buffer(4096+32)
    out_sz = ctypes.c_int(4096+32)
    for in_buf in iter(lambda: fp_in.read(4096), ""):
        ret = openssl.EVP_EncryptUpdate(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz), 
                                        ctypes.c_char_p(in_buf), ctypes.c_int(len(in_buf)))
        assert ret > 0
        fp_out.write(out_buf[:out_sz.value])
    ret = openssl.EVP_EncryptFinal(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz))
    assert ret > 0
    fp_out.write(out_buf[:out_sz.value])

def decrypt(symmetric_iv, symmetric_key, fp_in, fp_out):
    evp_cipher_ctx = EVP_CIPHER_CTX()
    openssl.EVP_CIPHER_CTX_init(ctypes.byref(evp_cipher_ctx))
    ret = openssl.EVP_DecryptInit(ctypes.byref(evp_cipher_ctx), openssl.EVP_aes_256_ctr(),
                                  ctypes.c_char_p(symmetric_key), ctypes.c_char_p(symmetric_iv))
    assert ret > 0
    out_buf = ctypes.create_string_buffer(4096+32)
    out_sz = ctypes.c_int(4096+32)
    for in_buf in iter(lambda: fp_in.read(4096), ""):
        ret = openssl.EVP_DecryptUpdate(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz), 
                                        ctypes.c_char_p(in_buf), ctypes.c_int(len(in_buf)))
        print ret
        assert ret > 0
        fp_out.write(out_buf[:out_sz.value])
    ret = openssl.EVP_DecryptFinal(ctypes.byref(evp_cipher_ctx), out_buf, ctypes.byref(out_sz))
    assert ret > 0
    fp_out.write(out_buf[:out_sz.value])
