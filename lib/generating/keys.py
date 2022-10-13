#!/usr/bin/python

""""
ilfocore.lib.generating.keys
===============

Provides keys generation support for ilfocore
"""

from base64 import b64encode
from secrets import token_bytes as random
from types import FunctionType, NoneType
from typing import Tuple
import ecies
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Util.Padding import pad
from ..demo import demo_keys
from ..exceptions import AlgorithmError, DemoError, KeyFormatError


def genkeys_RSA(randfunc: FunctionType, bits=2048) -> Tuple[bytes, bytes]:
    """Generate RSA keys in PEM"""
    key = RSA.generate(bits, randfunc)
    pk = key.public_key().export_key(format='PEM')
    sk = key.export_key(format='PEM')
    return pk, sk


def genkeys_DSA(randfunc: FunctionType, bits=2048) -> Tuple[bytes, bytes]:
    """Generate DSA keys in PEM"""
    key = DSA.generate(bits, randfunc)
    pk = key.public_key().export_key(format='PEM')
    sk = key.export_key(format='PEM')
    return pk, sk


def genkeys_Ed25519(randfunc: FunctionType) -> Tuple[bytes, bytes]:
    """Generate Ed25519 keys in PEM"""
    key = ECC.generate(curve='ed25519', randfunc=randfunc)
    pk = key.public_key().export_key(format='PEM')
    sk = key.export_key(format='PEM')
    return pk.encode('latin-1'), sk.encode('latin-1')


def genkeys_ECIES(randfunc: FunctionType) -> Tuple[bytes, bytes]:
    """Generate secp256k1 keys in PEM"""
    GROUP_ORDER = (
        b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
        b'\xfe\xba\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06AA'
    )
    ZERO = b'\x00'
    secret = GROUP_ORDER
    while secret <= ZERO or secret >= GROUP_ORDER:
        secret = randfunc(32)
    key = ecies.PrivateKey(secret)
    pk = key.public_key.format()
    PEM_HEADER = b'-----BEGIN PUBLIC KEY-----\n'
    PEM_FOOTER = b'\n-----END PUBLIC KEY-----'
    pk = PEM_HEADER + b64encode(pk) + PEM_FOOTER
    sk = key.to_pem()
    return pk, sk


def genkeys_AES_128(randfunc: FunctionType) -> Tuple[NoneType, bytes]:
    return None, randfunc(16)


def genkeys_AES_192(randfunc: FunctionType) -> Tuple[NoneType, bytes]:
    return None, randfunc(24)


def genkeys_AES_256(randfunc: FunctionType) -> Tuple[NoneType, bytes]:
    return None, randfunc(32)


def genkeys_demo(randfunc: FunctionType, bits=2048) -> Tuple[bytes, bytes]:
    """Generate demo keys"""
    raise DemoError("demo cannot be used.")

    key = demo_keys.generate(bits, randfunc)
    pk = key.public_key().export_key()
    sk = key.export_key()
    return pk, sk


GEN_KEYS = {
    'RSA': genkeys_RSA,
    'DSA': genkeys_DSA,
    'Ed25519': genkeys_Ed25519,
    'ECIES': genkeys_ECIES,
    'AES-128': genkeys_AES_128,
    'AES-192': genkeys_AES_192,
    'AES-256': genkeys_AES_256
    # 'demo': genkeys_demo
}


def getpk_RSA(sk: bytes) -> bytes:
    """Get RSA public key from private key"""
    sk = RSA.import_key(sk)
    pk = sk.public_key().export_key(format='PEM')
    return pk


def getpk_DSA(sk: bytes) -> bytes:
    """Get DSA public key from private key"""
    sk = DSA.import_key(sk)
    pk = sk.public_key().export_key(format='PEM')
    return pk


def getpk_Ed25519(sk: bytes) -> bytes:
    """Get Ed25519 public key from private key"""
    sk = ECC.import_key(sk)
    pk = sk.public_key().export_key(format='PEM')
    return pk.encode('latin-1')


def getpk_ECIES(sk: bytes) -> bytes:
    """Get secp256k1 public key from private key"""
    sk = ecies.PrivateKey.from_pem(sk)
    pk = sk.public_key.format()
    PEM_HEADER = b'-----BEGIN PUBLIC KEY-----\n'
    PEM_FOOTER = b'\n-----END PUBLIC KEY-----'
    pk = PEM_HEADER + b64encode(pk) + PEM_FOOTER
    return pk


def getpk_demo(sk: bytes) -> bytes:
    """Get demo public key from private key"""
    raise DemoError("demo cannot be used.")

    sk = demo_keys.import_key(sk)
    pk = sk.public_key().export_key()
    return pk


GET_PK = {
    'RSA': getpk_RSA,
    'DSA': getpk_DSA,
    'Ed25519': getpk_Ed25519,
    'ECIES': getpk_ECIES
    # 'demo': getpk_demo
}


def _checkKey(key: bytes, block_size: int) -> bytes:
    if len(key) <= block_size:
        return pad(key, block_size, 'pkcs7')
    raise KeyFormatError("Key is too long")


def getkey_AES_128(key: bytes):
    """Get PKCS7 padded AES-128 key"""
    return _checkKey(key, 16)


def getkey_AES_192(key: bytes):
    """Get PKCS7 padded AES-192 key"""
    return _checkKey(key, 24)


def getkey_AES_256(key: bytes):
    """Get PKCS7 padded AES-256 key"""
    return _checkKey(key, 32)


GET_KEY = {
    'AES-128': getkey_AES_128,
    'AES-192': getkey_AES_192,
    'AES-256': getkey_AES_256
}


ALGORITHMS = tuple(GEN_KEYS.keys())
ASYMMETRIC_ALGORITHMS = tuple(GET_PK.keys())
SYMMETRIC_ALGORITHMS = tuple(GET_KEY.keys())
AE_KEY_ALGORITHMS = ('RSA', 'ECIES')
SIG_KEY_ALGORITHMS = ('RSA', 'DSA', 'Ed25519')


def genkeys(algorithm: str, randfunc: FunctionType = random,
            *args, **kwargs) -> bytes:
    """Generate keys"""
    if gen_method := GEN_KEYS.get(algorithm):
        return gen_method(randfunc, *args, **kwargs)
    raise AlgorithmError("Unsupported key algorithm")


def getpk(algorithm: str, sk: bytes, *args, **kwargs) -> bytes:
    """Get public key from private key"""
    if get_method := GET_PK.get(algorithm):
        return get_method(sk, *args, **kwargs)
    raise AlgorithmError("Unsupported key algorithm")


def getkey(algorithm: str, unpad_key: bytes, *args, **kwargs) -> bytes:
    """Get padded key"""
    if get_method := GET_KEY.get(algorithm):
        return get_method(unpad_key, *args, **kwargs)
    raise AlgorithmError("Unsupported key algorithm")
