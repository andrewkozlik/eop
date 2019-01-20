# eop

Computing the issuer public key
===============================
Usage:
```bash
 ./compute_issuer_public_key.py certificate_file
```
This program reads the certificate and computes the public
key of the certificate issuer. The computed key is written
as a PEM encoded value of type SubjectPublicKeyInfo into a
file in the working directory.
