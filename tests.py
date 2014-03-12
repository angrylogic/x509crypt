#!/usr/bin/python

import unittest
import tempfile
import shutil
import random
import os

from x509crypt import asymmetric, symmetric, encoder

class CryptoTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = os.path.join(os.path.dirname(__file__), "temp")
        os.mkdir(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def temp_file(self, name):
        """Return the path to a tempfile for the test."""
        return os.path.join(self.temp_dir, name)

    def resource(self, name):
        """Return a test resource asserting it exists."""
        path = os.path.join(os.path.dirname(__file__), "test-resources", name)
        self.assertTrue(os.path.exists(path))
        return path

    def test_load_certificate(self):
        """Test loading a certificate context."""
        with asymmetric.certificate(self.resource("test.pem")) as ectx:
            self.assertTrue(ectx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: asymmetric.certificate("null.pem").__enter__())

    def test_load_privatekey(self):
        """Test loading a private key context."""
        with asymmetric.private_key(self.resource("test.key")) as dctx:
            self.assertTrue(dctx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: asymmetric.private_key("null.key").__enter__())

    def test_load_password_privatekey(self):
        """Test loading a password protected private key."""
        with asymmetric.private_key(self.resource("test-password.key"), "password") as dctx:
            self.assertTrue(dctx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: asymmetric.private_key("test-password.key",
                                                         "incorrect-password").__enter__())
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: asymmetric.private_key("null.key").__enter__())

    def test_asymmetric_encrypt_decrypt(self):
        """Test encryption and decryption with asymmetric keys."""
        test_string = os.urandom(32)
        test_long_string = os.urandom(1024)
        with asymmetric.certificate(self.resource("test.pem")) as ectx, \
                asymmetric.private_key(self.resource("test.key")) as dctx:
            encrypted_string = asymmetric.encrypt(ectx, test_string)
            decrypted_string = asymmetric.decrypt(dctx, encrypted_string)
            self.assertEquals(decrypted_string, test_string)
            self.assertRaises(asymmetric.AsymmetricCryptoError,
                              lambda: asymmetric.encrypt(ectx, test_long_string))

    def test_symmetric_encrypt_decrypt(self):
        """Test symmetric encryption."""
        test_iv = os.urandom(16)
        test_key = os.urandom(32)

        ifile = tempfile.TemporaryFile()
        ifile.write(os.urandom(1024*16))
        ifile.seek(0)

        efile = tempfile.TemporaryFile()
        symmetric.encrypt(test_iv, test_key, ifile, efile)
        efile.seek(0)
        ifile.seek(0)

        dfile = tempfile.TemporaryFile()
        symmetric.decrypt(test_iv, test_key, efile, dfile)
        dfile.seek(0)

        self.assertEquals(ifile.read(), dfile.read())

    def test_header_processing(self):
        """Test encoding and decoding file metadata."""
        ifile = tempfile.TemporaryFile()
        key = os.urandom(random.randrange(1024))
        iv = os.urandom(random.randrange(1024))
        encoder.write_header(ifile, iv, key)
        ifile.seek(0)
        header = encoder.read_header(ifile)
        self.assertEquals(header.symmetric_iv, iv)
        self.assertEquals(header.encrypted_symmetric_key, key)

    def test_open_writer_helper(self):
        """Test open_writer_helper for leaking files."""
        try:
            self.assertTrue(not os.path.exists(self.temp_file("SUCCESS")))
            with encoder.open_writer_helper(self.temp_file("SUCCESS")) as handle:
                pass
            self.assertTrue(os.path.exists(self.temp_file("SUCCESS")))
        finally:
            if os.path.exists(self.temp_file("SUCCESS")):
                os.unlink(self.temp_file("SUCCESS"))

        class TestException(Exception):
            pass
        self.assertTrue(not os.path.exists(self.temp_file("FAILURE")))
        try:
            with encoder.open_writer_helper(self.temp_file("FAILURE")) as handle:
                raise TestException
        except TestException:
            self.assertTrue(not os.path.exists(self.temp_file("FAILURE")))

if __name__ == "__main__":
    unittest.main()
