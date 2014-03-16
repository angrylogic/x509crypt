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

TAG_SIZE = 16

# pylint: disable-msg=C0103
FileMetaData = namedtuple("FileMetaData", ("symmetric_iv", "encrypted_symmetric_key", "tag"))

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

def tag_writer(file_ptr):
    """Return a function suitable for writing the tag when its ready.  This must be called immediately after write_header."""
    start_pos = file_ptr.tell() - TAG_SIZE
    def write_tag(tag):
        assert len(tag) == TAG_SIZE
        file_ptr.seek(start_pos)
        file_ptr.write(tag)
    return write_tag

def write_header(file_ptr, iv, key):
    """Write out a header to a file with the IV and encrypted symmetric key."""
    file_ptr.write(struct.pack(">I", len(iv)))
    file_ptr.write(iv)
    file_ptr.write(struct.pack(">I", len(key)))
    file_ptr.write(key)
    file_ptr.write(struct.pack(">I", TAG_SIZE))
    file_ptr.write("\00" * TAG_SIZE)

def read_header(file_ptr):
    """Read back a header from a file."""
    iv_size = struct.unpack(">I", file_ptr.read(struct.calcsize("I")))[0]
    symmetric_iv = file_ptr.read(iv_size)
    assert len(symmetric_iv) == iv_size
    key_size = struct.unpack(">I", file_ptr.read(struct.calcsize("I")))[0]
    encrypted_symmetric_key = file_ptr.read(key_size)
    assert len(encrypted_symmetric_key) == key_size
    tag_size = struct.unpack(">I", file_ptr.read(struct.calcsize("I")))[0]
    tag = file_ptr.read(tag_size)
    assert len(tag) == tag_size
    return FileMetaData(symmetric_iv, encrypted_symmetric_key, tag)
