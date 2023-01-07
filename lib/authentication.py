""""
ilfocore.lib.authentication

Provides message authentication support for ilfocore.

Example

>>> msg = b'message'
>>> dig = get_digest('md5').generate()
>>> dig.digest(msg).hex()
'78e731027d8fd50ed642340b7c9a63b3'
>>> dig = get_mac('hmac-md5').from_bytes(b'a secret mac key')
>>> dig.digest(msg).hex()
'05232196927e8375836f4b992ba9aa85'

"""

import hashlib
import hmac
from abc import ABCMeta, abstractmethod
from secrets import token_bytes as random
from typing import Self
from .exceptions import AlgorithmError


class Digest(metaclass=ABCMeta):

    """Digest class."""

    @classmethod
    def generate(cls) -> Self:
        """Generate a new object."""
        return cls()

    @classmethod
    @property
    @abstractmethod
    def name(cls) -> str:
        """Algorithm name."""

    @classmethod
    @property
    @abstractmethod
    def digest_size(cls) -> int:
        """The size of the digest in bytes."""

    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        """Return the digest of the data."""


class NoDigest(Digest):

    """No MAC."""

    name = 'none'
    digest_size = 0

    def digest(self, data: bytes) -> bytes:
        """Return empty bytes."""
        return b''


class DigestMetaclass(ABCMeta):

    """Hash digest Metaclass."""

    def __new__(cls, name, bases, attrs, alg):
        attrs['name'] = alg
        attrs['digest_size'] = hashlib.new(alg).digest_size
        attrs['digest'] = lambda self, data: hashlib.new(alg, data).digest()
        return ABCMeta.__new__(cls, name, bases, attrs)

    def __init__(cls, name, bases, attrs, _):
        super().__init__(name, bases, attrs)


digest_algorithms = {'none': NoDigest}
_hash_algorithms = (
    'MD5',
    'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
    'BLAKE2b', 'BLAKE2s',
    'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512'
)
__sha3 = (('sha3-224', 'SHA3_224'), ('sha3-256', 'SHA3_256'),
          ('sha3-384', 'SHA3_384'), ('sha3-512', 'SHA3_512'))

for __name in _hash_algorithms:
    __alg = __name.lower()
    exec(f"{__name} = DigestMetaclass('{__name}',"
         f" (Digest,), {{}}, '{__alg}')")
    digest_algorithms[__alg] = eval(__name)
for __alg, __name in __sha3:
    digest_algorithms[__alg] = eval(__name)


class MACKey(Digest):

    """Key for MAC."""

    def __init__(self, key: object):
        self._key = key

    @property
    def key(self) -> object:
        """Return the key."""
        return self._key

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Dump key to bytes."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load key from bytes."""


class HMACKey(MACKey):
    # pylint: disable=W0223
    """HMAC key base class."""

    def to_bytes(self) -> bytes:
        """Dump key to bytes."""
        return self._key

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load key from bytes."""
        return cls(key_bytes)


class HMACMetaclass(ABCMeta):

    """Hash digest Metaclass."""

    def __new__(cls, name, bases, attrs, alg):
        attrs['name'] = 'hmac-' + alg
        attrs['digest_size'] = hashlib.new(alg).digest_size
        attrs['digest'] = lambda self, data: hmac.digest(
            self._key, data, alg)
        attrs['generate'] = classmethod(lambda cls:
                                        cls(random(cls.digest_size)))
        return ABCMeta.__new__(cls, name, bases, attrs)

    def __init__(cls, name, bases, attrs, _):
        super().__init__(name, bases, attrs)


mac_algorithms = {}

for __name in _hash_algorithms:
    __alg = __name.lower()
    __name = 'HMAC' + __name
    exec(f"{__name} = HMACMetaclass('{__name}',"
         f" (HMACKey, Digest), {{}}, '{__alg}')")
    mac_algorithms['hmac-' + __alg] = eval(__name)
for __alg, __name in __sha3:
    mac_algorithms['hmac-' + __alg] = eval('HMAC' + __name)

algorithms = set(mac_algorithms)


def get_digest(algorithm: str) -> type[Digest]:
    """Get digest class."""
    if digest := digest_algorithms.get(algorithm.lower()):
        return digest
    raise AlgorithmError("Unsupported digest algorithm")


def get_mac(algorithm: str) -> type[MACKey]:
    """Get MAC key class."""
    if mac := mac_algorithms.get(algorithm.lower()):
        return mac
    raise AlgorithmError("Unsupported message authentication algorithm")


# Cleanup locals()
del __alg, __name
