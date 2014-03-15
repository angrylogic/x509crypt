#!/usr/bin/python

import unittest
import tempfile
import shutil
import subprocess
import random
import os

from x509crypt.asymmetric import AsymmetricContext
from x509crypt import asymmetric, symmetric, encoder

class TestHelpers(unittest.TestCase):

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

class CommandLineTests(TestHelpers):

    def test_encrypt_with_certificate(self):
        # Call with python for virtualenv to function properly.
        input_file_path = self.temp_file("input")
        open(input_file_path, "w").write(os.urandom(1024*16))
        subprocess.check_call(["python", "x509crypt_cmd", "encrypt", self.resource("test.pem"), input_file_path, self.temp_file("output.enc")])
        subprocess.check_call(["python", "x509crypt_cmd", "decrypt", self.resource("test.key"), self.temp_file("output.enc"), self.temp_file("output.dec")])
        self.assertEquals(open(self.temp_file("output.dec")).read(), open(input_file_path).read())

    def test_encrypt_with_certificate_and_password(self):
        # Call with python for virtualenv to function properly.
        input_file_path = self.temp_file("input")
        open(input_file_path, "w").write(os.urandom(1024*16))
        subprocess.check_call(["python", "x509crypt_cmd", "encrypt", self.resource("test-password.pem"), input_file_path, self.temp_file("output.enc")])
        subprocess.check_call(["python", "x509crypt_cmd", "decrypt", "--password=password", self.resource("test-password.key"), self.temp_file("output.enc"), self.temp_file("output.dec")])
        self.assertEquals(open(self.temp_file("output.dec")).read(), open(input_file_path).read())

class LibraryTests(TestHelpers):

    def test_load_certificate(self):
        """Test loading a certificate context."""
        with AsymmetricContext.from_certificate(self.resource("test.pem")) as ectx:
            self.assertTrue(ectx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: AsymmetricContext.from_certificate("null.pem").__enter__())

    def test_load_privatekey(self):
        """Test loading a private key context."""
        with AsymmetricContext.from_private_key(self.resource("test.key")) as dctx:
            self.assertTrue(dctx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: AsymmetricContext.from_private_key("null.key").__enter__())

    def test_load_password_privatekey(self):
        """Test loading a password protected private key."""
        with AsymmetricContext.from_private_key(self.resource("test-password.key"), "password") as dctx:
            self.assertTrue(dctx)
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: AsymmetricContext.from_private_key("test-password.key",
                                                         "incorrect-password").__enter__())
        self.assertRaises(asymmetric.AsymmetricCryptoError,
                          lambda: AsymmetricContext.from_private_key("null.key").__enter__())

    def test_asymmetric_encrypt_decrypt(self):
        """Test encryption and decryption with asymmetric keys."""
        test_string = os.urandom(32)
        test_long_string = os.urandom(1024)
        with AsymmetricContext.from_certificate(self.resource("test.pem")) as pub_context, \
                AsymmetricContext.from_private_key(self.resource("test.key")) as key_context:
            encrypted_string = pub_context.encrypt(test_string)
            decrypted_string = key_context.decrypt(encrypted_string)
            self.assertEquals(decrypted_string, test_string)
            self.assertRaises(asymmetric.AsymmetricCryptoError,
                              lambda: pub_context.encrypt(test_long_string))

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

        # not the best test but at least looking for an exception
        with encoder.open_writer_helper("-") as handle:
            handle.write("some test data to stdout")

if __name__ == "__main__":
    unittest.main()
