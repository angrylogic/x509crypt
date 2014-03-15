#!/usr/bin/python

"""This module contains utility functions for writing and reading
headers from x509crypt formatted files."""

import os
import shutil
import struct
import sys
import tempfile
from collections import namedtuple
from contextlib import contextmanager

# pylint: disable-msg=C0103
FileMetaData = namedtuple("FileMetaData", ("symmetric_iv", "encrypted_symmetric_key"))

@contextmanager
def open_writer_helper(final_file_name):
    """Open a writer that will rename on success and cleanup on failure."""
    temp_file = tempfile.NamedTemporaryFile()
    yield temp_file
    if final_file_name == "-":
        temp_file.seek(0)
        shutil.copyfileobj(temp_file, sys.stdout)
    else:
        os.link(temp_file.name, final_file_name)

def write_header(file_ptr, enc_iv, enc_key):
    """Write out a header to a file with the IV and encrypted symmetric key."""
    file_ptr.write(struct.pack(">I", len(enc_iv)))
    file_ptr.write(enc_iv)
    file_ptr.write(struct.pack(">I", len(enc_key)))
    file_ptr.write(enc_key)

def read_header(file_ptr):
    """Read back a header from a file."""
    iv_size = struct.unpack(">I", file_ptr.read(struct.calcsize("I")))[0]
    symmetric_iv = file_ptr.read(iv_size)
    assert len(symmetric_iv) == iv_size
    key_size = struct.unpack(">I", file_ptr.read(struct.calcsize("I")))[0]
    encrypted_symmetric_key = file_ptr.read(key_size)
    assert len(encrypted_symmetric_key) == key_size
    return FileMetaData(symmetric_iv, encrypted_symmetric_key)
