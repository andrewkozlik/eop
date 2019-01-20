#!/usr/bin/python3
#
# Copyright (c) 2019 Andrew R. Kozlik
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from fastecdsa.curve import P521
from fastecdsa.point import Point
from fastecdsa.asn1 import encode_public_key
from asn1crypto.x509 import Certificate
from asn1crypto.core import Sequence
from asn1crypto.pem import unarmor
from hashlib import sha512, sha1
from os import sys, path

def key_id(point):
    public_key_info = Sequence.load(unarmor(encode_public_key(point).encode())[2])
    return sha1(public_key_info[1].contents[1:]).digest()


def compute_issuer_public_keys(cert):
    sig = Sequence.load(cert["signature_value"].native)
    r = sig[0].native
    s = sig[1].native

    tbs_hash = sha512(cert["tbs_certificate"].dump()).digest()
    z = int.from_bytes(tbs_hash, byteorder="big")
    u1 = (z * pow(s, P521.q - 2, P521.q)) % P521.q
    u2 = (pow(r, P521.q - 2, P521.q) * s) % P521.q

    ky = (r**3 + P521.a * r + P521.b) % P521.p
    y0 = pow(ky, (P521.p + 1)//4, P521.p)
    y1 = P521.p - y0

    Q0 = u2 * (Point(r, y0, curve=P521) - u1*P521.G)
    Q1 = u2 * (Point(r, y1, curve=P521) - u1*P521.G)

    if key_id(Q0) == cert.authority_key_identifier:
        issuer_pub = Q0
    elif key_id(Q1) == cert.authority_key_identifier:
        issuer_pub = Q1

    if issuer_pub:
        return (issuer_pub,)
    else:
        return (Q0, Q1)


if len(sys.argv) == 1:
    print("Usage: {} certificate_file".format(sys.argv[0]))
    print()
    print("This program reads a certificate and computes the public")
    print("key of the certificate issuer. The computed key is written")
    print("as a PEM encoded value of type SubjectPublicKeyInfo into a")
    print("file in the working directory.")
    exit()

cert_paths = sys.argv[1:]
for cert_path in cert_paths:
    with open(cert_path, "rb") as f:
        cert = Certificate.load(f.read())

    name = path.splitext(path.basename(cert_path))[0]
    for i, point in enumerate(compute_issuer_public_keys(cert)):
        with open("{}-issuer{}.pub".format(name, i), "wb") as f:
            f.write(encode_public_key(point).encode())
            f.write(b"\n")
