#!/usr/bin/python

import struct
import tempfile
import os
from contextlib import contextmanager
from collections import namedtuple

FileMetaData = namedtuple("FileMetaData", ("symmetric_iv", "encrypted_symmetric_key", "tag"))

TAG_SIZE = 16

@contextmanager
def open_writer_helper(final_file_name):
    """Open a writer that will rename on success and cleanup on failure."""
    temp_file = tempfile.NamedTemporaryFile()
    yield temp_file
    os.link(temp_file.name, final_file_name)

def tag_writer(fp):
    """Return a function suitable for writing the tag when its ready.  This must be called immediately after write_header."""
    start_pos = fp.tell() - TAG_SIZE
    def write_tag(tag):
        assert len(tag) == TAG_SIZE
        fp.seek(start_pos)
        fp.write(tag)
    return write_tag

def write_header(fp, iv, key):
    """Write out a header to a file with the IV and encrypted symmetric key."""
    fp.write(struct.pack(">I", len(iv)))
    fp.write(iv)
    fp.write(struct.pack(">I", len(key)))
    fp.write(key)
    fp.write(struct.pack(">I", TAG_SIZE))
    fp.write("\00" * TAG_SIZE)

def read_header(fp):
    """Read back a header from a file."""
    iv_size = struct.unpack(">I", fp.read(struct.calcsize("I")))[0]
    symmetric_iv = fp.read(iv_size)
    assert len(symmetric_iv) == iv_size
    key_size = struct.unpack(">I", fp.read(struct.calcsize("I")))[0]
    encrypted_symmetric_key = fp.read(key_size)
    assert len(encrypted_symmetric_key) == key_size
    tag_size = struct.unpack(">I", fp.read(struct.calcsize("I")))[0]
    tag = fp.read(tag_size)
    assert len(tag) == tag_size
    return FileMetaData(symmetric_iv, encrypted_symmetric_key, tag)
