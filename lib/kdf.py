#!/usr/bin/python

""""
ilfocore.lib.kdf
===============

Provides key derivation support for ilfocore.

Example

>>> key = b'a secret AES key'
>>> kdf = get_kdf('hkdf_expand-md5').generate()
>>> dkey = kdf.derive(key, 32)
>>> dkey.hex()
'543f886fd48457656236bf867de8b65b90ad205ae98650ad6544e98d6e3ec5e1'

"""

from abc import ABCMeta, abstractmethod
from typing import Self
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import concatkdf, hkdf, x963kdf
from .exceptions import AlgorithmError


class KDF(metaclass=ABCMeta):

    """Key derivation function class."""

    @classmethod
    def generate(cls) -> Self:
        """Generate a new object."""
        return cls()

    @classmethod
    @property
    @abstractmethod
    def name(cls) -> str:
        """Algorithm name."""

    @abstractmethod
    def derive(self, key: bytes, length: int) -> bytes:
        """Return the derived key."""


class HashKDF(KDF):

    """KDF uses classes from hashes."""

    @classmethod
    @property
    @abstractmethod
    def hash(cls) -> type[hashes.HashAlgorithm]:
        """Return hash class."""


class ConcatKDFHash(HashKDF):
    # pylint: disable=W0223
    """ConcatKDF."""

    name = 'concatkdf_hash-'

    def derive(self, key: bytes, length: int) -> bytes:
        """Derive the key."""
        return concatkdf.ConcatKDFHash(self.hash(), length, None).derive(key)


class ConcatKDFHMAC(HashKDF):
    # pylint: disable=W0223
    """ConcatKDF."""

    name = 'concatkdf_hmac-'

    def derive(self, key: bytes, length: int) -> bytes:
        """Derive the key."""
        return concatkdf.ConcatKDFHMAC(
            self.hash(), length, None, None).derive(key)


class HKDFExtract(HashKDF):
    # pylint: disable=W0223
    """HKDF extract."""

    name = 'hkdf_extract-'

    def derive(self, key: bytes, length: int) -> bytes:
        """Derive the key."""
        return hkdf.HKDF(self.hash(), length, None, None).derive(key)


class HKDFExpand(HashKDF):
    # pylint: disable=W0223
    """HKDF expand."""

    name = 'hkdf_expand-'

    def derive(self, key: bytes, length: int) -> bytes:
        """Derive the key."""
        return hkdf.HKDFExpand(self.hash(), length, None).derive(key)


class X963KDF(HashKDF):
    # pylint: disable=W0223
    """ANSI X9.63 Key Derivation Function."""

    name = 'x963kdf-'

    def derive(self, key: bytes, length: int) -> bytes:
        """Derive the key."""
        return x963kdf.X963KDF(self.hash(), length, None).derive(key)


kdfs = {}
__hash_algorithms = ('SHA1', 'SHA224', 'SHA256', 'SHA384', 'MD5', 'SM3')


def __define_hash_kdfs(kdf_class: type[HashKDF]):
    kdf_class_name = kdf_class.__name__
    kdf_name = kdf_class.name
    for hash_class_name in __hash_algorithms:
        name = kdf_class_name + hash_class_name
        hash_name = hash_class_name.lower()
        kdf_alg_name = kdf_name + hash_name
        exec(f"global {name}")
        exec(f"""class {name}({kdf_class_name}):
                 name = '{kdf_alg_name}'
                 hash = hashes.{hash_class_name}
                 hash.name = '{hash_name}'
             """)
        kdfs[kdf_alg_name] = eval(name)


__define_hash_kdfs(HKDFExtract)
__define_hash_kdfs(HKDFExpand)
__define_hash_kdfs(ConcatKDFHash)
__define_hash_kdfs(ConcatKDFHMAC)
__define_hash_kdfs(X963KDF)

algorithms = set(kdfs)


def get_kdf(algorithm: str) -> type[KDF]:
    """Get KDF class."""
    if kdf := kdfs.get(algorithm.lower()):
        return kdf
    raise AlgorithmError("Unsupported key exchange algorithm")


# Cleanup locals()
del __define_hash_kdfs, __hash_algorithms
