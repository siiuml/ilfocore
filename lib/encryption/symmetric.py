#!/usr/bin/python

""""
ilfocore.lib.encryption.symmetric
===============

Provides symmetric encryption support for ilfocore
"""

from types import FunctionType
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ..demo import demo_symmetric_encryption_algorithm
from ..exceptions import AlgorithmError, DemoError

# DEFAULT_IV = b''.zfill(16)
DEFAULT_IV = b'0000000000000000'


def encrypt_AES(plaintext: bytes, key: bytes,
                iv: bytes = DEFAULT_IV) -> bytes:
    """Encrypt plaintext with key and AES (CBC mode)
       len(iv) == 16
    """
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    return ciphertext


def encrypt_demo(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext with key and demo encryption algorithm"""
    raise DemoError("demo cannot be used.")

    ciphertext = demo_symmetric_encryption_algorithm.new(
        key).encrypt(plaintext)
    return ciphertext


ENCRYPTION_ALGORITHMS = {
    'AES-128': encrypt_AES,
    'AES-192': encrypt_AES,
    'AES-256': encrypt_AES
    # 'demo': encrypt_demo
}


def decrypt_AES(ciphertext: bytes, key: bytes,
                iv: bytes = DEFAULT_IV) -> bytes:
    """Decrypt ciphertext with key and AES (CBC mode)"""
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    return unpad(plaintext, 16)

def decrypt_demo(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext with key and demo encryption algorithm"""
    raise DemoError("demo cannot be used.")

    plaintext = demo_symmetric_encryption_algorithm.new(
        key).encrypt(ciphertext)
    return plaintext


DECRYPTION_ALGORITHMS = {
    'AES-128': decrypt_AES,
    'AES-192': decrypt_AES,
    'AES-256': decrypt_AES
    # 'demo': decrypt_demo
}

ALGORITHMS = tuple(ENCRYPTION_ALGORITHMS.keys())


def getfunc(algorithm: str) -> Tuple[FunctionType, FunctionType]:
    """Get encrypt method and decrypt method"""
    if algorithm in ALGORITHMS:
        return (ENCRYPTION_ALGORITHMS[algorithm],
                DECRYPTION_ALGORITHMS[algorithm])
    raise AlgorithmError("Unsupported encryption algorithm")


def encrypt(algorithm: str, plaintext: bytes, key: bytes,
            *args, **kwargs) -> bytes:
    """Encrypt plaintext with key"""
    if encryption_algorithm := ENCRYPTION_ALGORITHMS.get(algorithm):
        return encryption_algorithm(plaintext, key, *args, **kwargs)
    raise AlgorithmError("Unsupported encryption algorithm")


def decrypt(algorithm: str, ciphertext: bytes, key: bytes,
            *args, **kwargs) -> bytes:
    """Decrypt ciphertext with key"""
    if decryption_algorithm := DECRYPTION_ALGORITHMS.get(algorithm):
        return decryption_algorithm(ciphertext, key, *args, **kwargs)
    raise AlgorithmError("Unsupported encryption algorithm")
