#!/usr/bin/python

""""
ilfocore.lib.demo.demo_signature_algorithm
===============

Demostration of signature algorithm
"""


class DemoSigScheme:
    def __init__(self, key: bytes):
        self._key = key

    def sign(self, digest: bytes) -> bytes:
        return b''

    def verify(self, digest: bytes, signature: bytes):
        pass


def new(key: bytes) -> DemoSigScheme:
    return DemoSigScheme(key)
