## x509crypt
This package contains a library ``x509crypt`` and a command line tool
``x509crypt_cmd`` for easily encrypting files under an X509 certificate.
The actual contents of the files are encrypted using the aes-cbc-256
symmetric cipher. It was more or less an attempt to play with the
OpenSSL EVP API through python ctypes. Currently only certificates and
keys encoded in the PEM format are accepted.

### Usage

Encrypt some document so only Google can read it:

    openssl s_client -connect encrypted.google.com:443 < /dev/null | openssl x509 -text > google.pem
    x509crypt_cmd encrypt google.pem INPUT OUTPUT

Decrypt the same document with Google's private key:

    x509crypt_cmd decrypt /path/to/google.key INPUT OUTPUT
