#!/usr/bin/python

""""
ilafalseone.lib.demo.demo_keys
===============

Demostration of generating key for asymmetric encryption algorithm
"""

import os


class DemoKey:
    def __init__(self, secret):
        self._secret = secret

    def public_key(self):
        return DemoKey(self._secret)

    def export_key(self) -> bytes:
        return self._secret


def import_key(sk: bytes) -> DemoKey:
    return DemoKey(sk)


def generate(bit=0, randfunc=None) -> DemoKey:
    if not randfunc:
        randfunc = os.urandom
    return DemoKey(randfunc(bit))
