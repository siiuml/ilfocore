#!/usr/bin/python

""""
ilfocore.lib.encryption.asymmetric
===============

Provides asymmetric encryption support for ilfocore
"""

from base64 import b64decode
import ecies
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from ..demo import demo_asymmetric_encryption_algorithm
from ..exceptions import AlgorithmError, DemoError


def encrypt_RSA(plaintext: bytes, pk: bytes) -> bytes:
    """Encrypt plaintext with public key and PKCS1 OAEP (RSA)"""
    key = RSA.import_key(pk)
    ciphertext = PKCS1_OAEP.new(key).encrypt(plaintext)
    return ciphertext


def encrypt_ECIES(plaintext: bytes, pk: bytes) -> bytes:
    """Encrypt plaintext with public key and ECC.
       public key in pem
    """
    pk = b''.join(pk.strip().splitlines()[1: -1])
    pk = b64decode(pk)
    return ecies.encrypt(pk, plaintext)


def encrypt_demo(plaintext: bytes, pk: bytes) -> bytes:
    """Encrypt plaintext with public key and demo encryption algorithm"""
    raise DemoError("demo cannot be used.")

    ciphertext = \
        demo_asymmetric_encryption_algorithm.new(pk).encrypt(plaintext)
    return ciphertext


ENCRYPTION_ALGORITHMS = {
    'RSA': encrypt_RSA,
    'ECIES': encrypt_ECIES
    # 'demo': encrypt_demo
}


def decrypt_RSA(ciphertext: bytes, sk: bytes) -> bytes:
    """Decrypt ciphertext with private key and PKCS1 OAEP"""
    key = RSA.import_key(sk)
    plaintext = PKCS1_OAEP.new(key).decrypt(ciphertext)
    return plaintext


def decrypt_ECIES(ciphertext: bytes, sk: bytes) -> bytes:
    """Decrypt ciphertext with private key and ECC.
       private key in PEM
    """
    key = ecies.PrivateKey.from_pem(sk).to_hex()
    return ecies.decrypt(key, ciphertext)


def decrypt_demo(ciphertext: bytes, sk: bytes) -> bytes:
    """Decrypt ciphertext with private key and demo encryption algorithm"""
    raise DemoError("demo cannot be used.")

    plaintext = \
        demo_asymmetric_encryption_algorithm.new(sk).encrypt(ciphertext)
    return plaintext


DECRYPTION_ALGORITHMS = {
    'RSA': decrypt_RSA,
    'ECIES': decrypt_ECIES
    # 'demo': decrypt_demo
}

ALGORITHMS = tuple(ENCRYPTION_ALGORITHMS.keys())


def encrypt(algorithm: str, plaintext: bytes, pk: bytes,
            *args, **kwargs) -> bytes:
    """Encrypt plaintext with public key"""
    if encryption_algorithm := ENCRYPTION_ALGORITHMS.get(algorithm):
        return encryption_algorithm(plaintext, pk, *args, **kwargs)
    raise AlgorithmError("Unsupported encryption algorithm")


def decrypt(algorithm: str, ciphertext: bytes, sk: bytes,
            *args, **kwargs) -> bytes:
    """Encrypt ciphertext with private key"""
    if decryption_algorithm := DECRYPTION_ALGORITHMS.get(algorithm):
        return decryption_algorithm(ciphertext, sk, *args, **kwargs)
    raise AlgorithmError("Unsupported encryption algorithm")
