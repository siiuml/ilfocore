#!/usr/bin/python

""""
ilfocore.lib.demo.demo_symmetric_encryption_algorithm
===============

Demostration of symmetric encryption algorithm
"""


class DemoCipher:
    def __init__(self, key: bytes):
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext


def new(key: bytes) -> DemoCipher:
    return DemoCipher(key)
