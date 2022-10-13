#!/usr/bin/python

""""
ilfocore.lib.signature
===============

Provides digital signature support for ilafalseone
"""

from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, DSS, eddsa
from Crypto.Hash import (
    HMAC,
    MD5,
    RIPEMD160,
    SHA1,
    SHA256,
    SHA384,
    SHA512)
from .demo import demo_signature_algorithm
from .exceptions import AlgorithmError, DemoError

HASH_METHODS = {
    'HMAC': HMAC.new,
    'MD5': MD5.new,
    'RIPEMD-160': RIPEMD160.new,
    'SHA-1': SHA1.new,
    'SHA-256': SHA256.new,
    'SHA-384': SHA384.new,
    'SHA-512': SHA512.new
}


class FakeHash:
    """An object not hashed."""

    def __init__(self, data, oid='2.16.840.1.101.3.4.2.3'):
        # 2.16.840.1.101.3.4.2.3 is the ASN.1 Object ID of SHA-512
        self.oid = oid
        self.data = data

    def digest(self):
        return self.data

    def __str__(self):
        return self.data

    def __repr__(self):
        return self.data


def _digest(data, hash_method):
    if hash_method:
        assert (hash := HASH_METHODS.get(hash_method)), (
            "Hash method not found")
        return hash(data)
    return FakeHash(data)


def sign_RSA(digest: bytes, sk: bytes) -> bytes:
    """Sign data digest with private key and RSA"""
    key = RSA.import_key(sk)
    signature = pkcs1_15.new(key).sign(digest)
    return signature


def _sign_NONEwithRSA(data, sk):
    return sign_RSA(_digest(data, None), sk)


def _sign_MD5withRSA(data, sk):
    return sign_RSA(_digest(data, 'MD5'), sk)


def _sign_SHA1withRSA(data, sk):
    return sign_RSA(_digest(data, 'SHA-1'), sk)


def _sign_SHA256withRSA(data, sk):
    return sign_RSA(_digest(data, 'SHA-256'), sk)


def _sign_SHA512withRSA(data, sk):
    return sign_RSA(_digest(data, 'SHA-512'), sk, )


def sign_DSA(digest: bytes, sk: bytes) -> bytes:
    """Sign data digest with private key and DSA"""
    key = DSA.import_key(sk)
    signature = DSS.new(key, 'fips-186-3').sign(digest)
    return signature


def _sign_NONEwithDSA(data, sk):
    return sign_DSA(_digest(data, None), sk)


def _sign_SHA1withDSA(data, sk):
    return sign_DSA(_digest(data, 'SHA-1'), sk)


def _sign_SHA256withDSA(data, sk):
    return sign_DSA(_digest(data, 'SHA-256'), sk)


def _sign_SHA512withDSA(data, sk):
    return sign_DSA(_digest(data, 'SHA-512'), sk)


def sign_Ed25519(digest: bytes, sk: bytes) -> bytes:
    """Sign data digest with private key and DSA"""
    key = ECC.import_key(sk)
    print(f"\n\nDIGEST: {digest}\n\n")
    signature = eddsa.new(key, 'rfc8032').sign(digest)
    return signature


def _sign_NONEwithEd25519(data, sk):
    return sign_Ed25519(data, sk)


def _sign_SHA512withEd25519(data, sk):
    return sign_Ed25519(_digest(data, 'SHA-512'), sk)


def sign_demo(digest: bytes, sk: bytes) -> bytes:
    """Sign data digest with private key and demo signature algorithm"""
    raise DemoError("demo cannot be used.")

    signature = demo_signature_algorithm.new(sk).sign(digest)
    return signature


def _sign_MD5withDemo(data, sk):
    return sign_demo(_digest(data, 'MD5'), sk)


SIGN_ALGORITHMS = {
    'NONEwithRSA': _sign_NONEwithRSA,
    'MD5withRSA': _sign_MD5withRSA,
    'SHA1withRSA': _sign_SHA1withRSA,
    'SHA256withRSA': _sign_SHA256withRSA,
    'SHA512withRSA': _sign_SHA512withRSA,
    'NONEwithDSA': _sign_NONEwithDSA,
    'SHA1withDSA': _sign_SHA1withDSA,
    'SHA256withDSA': _sign_SHA256withDSA,
    'SHA512withDSA': _sign_SHA512withDSA,
    'NONEwithEd25519': _sign_NONEwithEd25519,
    'SHA512withEd25519': _sign_SHA512withEd25519
    # 'MD5withDemo': _sign_MD5withDemo
}


def verify_RSA(digest: bytes, pk: bytes, signature: bytes):
    """Verify signature with data digest, public key and RSA"""
    key = RSA.importKey(pk)
    pkcs1_15.new(key).verify(digest, signature)


def _verify_NONEwithRSA(data, pk, signature):
    return verify_RSA(_digest(data, None), pk, signature)


def _verify_MD5withRSA(data, pk, signature):
    return verify_RSA(_digest(data, 'MD5'), pk, signature)


def _verify_SHA1withRSA(data, pk, signature):
    return verify_RSA(_digest(data, 'SHA-1'), pk, signature)


def _verify_SHA256withRSA(data, pk, signature):
    return verify_RSA(_digest(data, 'SHA-256'), pk, signature)


def _verify_SHA512withRSA(data, pk, signature):
    return verify_RSA(_digest(data, 'SHA-512'), pk, signature)


def verify_DSA(digest: bytes, pk: bytes, signature: bytes):
    """Verify signature with data digest, public key and DSA"""
    key = DSA.importKey(pk)
    DSS.new(key, 'fips-186-3').verify(digest, signature)


def _verify_NONEwithDSA(data, pk, signature):
    return verify_DSA(_digest(data, None), pk, signature)


def _verify_SHA1withDSA(data, pk, signature):
    return verify_DSA(_digest(data, 'SHA-1'), pk, signature)


def _verify_SHA256withDSA(data, pk, signature):
    return verify_DSA(_digest(data, 'SHA-256'), pk, signature)


def _verify_SHA512withDSA(data, pk, signature):
    return verify_DSA(_digest(data, 'SHA-512'), pk, signature)


def verify_Ed25519(digest: bytes, pk: bytes, signature: bytes):
    """Verify signature with data digest, public key and Ed25519"""
    key = ECC.import_key(pk)
    eddsa.new(key, 'rfc8032').verify(digest, signature)


def _verify_NONEwithEd25519(data, pk, signature):
    return verify_Ed25519(data, pk, signature)


def _verify_SHA512withEd25519(data, pk, signature):
    return verify_Ed25519(_digest(data, 'SHA-512'), pk, signature)


def verify_demo(digest: bytes, pk: bytes, signature: bytes):
    """Verify signature with data digest, public key
       and demo signature algorithm
    """
    raise DemoError("demo cannot be used.")

    demo_signature_algorithm.new(pk).verify(digest, signature)


def _verify_MD5withDemo(data, pk, signature):
    return verify_demo(_digest(data, 'MD5'), pk, signature)


VERIFY_ALGORITHMS = {
    'NONEwithRSA': _verify_NONEwithRSA,
    'MD5withRSA': _verify_MD5withRSA,
    'SHA1withRSA': _verify_SHA1withRSA,
    'SHA256withRSA': _verify_SHA256withRSA,
    'SHA512withRSA': _verify_SHA512withRSA,
    'NONEwithDSA': _verify_NONEwithDSA,
    'SHA1withDSA': _verify_SHA1withDSA,
    'SHA256withDSA': _verify_SHA256withDSA,
    'SHA512withDSA': _verify_SHA512withDSA,
    'NONEwithEd25519': _verify_NONEwithEd25519,
    'SHA512withEd25519': _verify_SHA512withEd25519
    # 'MD5withDemo': _verify_MD5withDemo
}

ALGORITHMS = tuple(SIGN_ALGORITHMS.keys())


def sign(algorithm: str, data: bytes, sk: bytes) -> bytes:
    """Sign data with private key"""
    if sign_algorithm := SIGN_ALGORITHMS.get(algorithm):
        return sign_algorithm(data, sk)
    raise AlgorithmError("Unsupported signature algorithm")


def verify(algorithm: str, data: bytes, pk: bytes, signature: bytes) -> bool:
    """Verify data with public key and signature"""
    if verify_algorithm := VERIFY_ALGORITHMS.get(algorithm):
        return verify_algorithm(data, pk, signature)
    raise AlgorithmError("Unsupported signature algorithm")
