""""
ilfocore.lib.cipher

Provides symmetric encryption support for ilfocore.

"""

from abc import ABCMeta, abstractmethod
from secrets import token_bytes as random
from typing import Self
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
from .exceptions import AlgorithmError


class SymmetricKey(metaclass=ABCMeta):

    """Symmetric key."""

    def __init__(self, key: object):
        self._key = key

    @property
    def key(self) -> object:
        """Return the key object."""
        return self._key

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Dump key to bytes."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load key from bytes."""

    @classmethod
    @abstractmethod
    def generate(cls) -> Self:
        """Generate a new key."""

    @classmethod
    @property
    @abstractmethod
    def key_size(cls) -> int:
        """Key byte length."""

    @classmethod
    @property
    @abstractmethod
    def name(self) -> str:
        """Algorithm name."""


class NoCipher(SymmetricKey):

    """No encryption."""

    name = 'none'
    key_size = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """No encryption."""
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """No decryption."""
        return ciphertext

    def to_bytes(self) -> bytes:
        """Return the key."""
        return self._key

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Return NoKey object."""
        return cls(key_bytes)

    @classmethod
    def generate(cls) -> Self:
        """Generate an empty key."""
        return cls(b'')


class AESKey(SymmetricKey):

    """AES symmetric key."""

    block_size = 128

    def __init__(self, key: bytes, iv=bytes(16)):
        super().__init__(key)
        self._iv = iv
        self._cipher = Cipher(AES(key), CBC(iv))
        self._padding = PKCS7(self.block_size)

    def encrypt(self, plaintext: bytes) -> bytes:
        """AES-CBC encryption."""
        padder = self._padding.padder()
        plaintext = padder.update(plaintext) + padder.finalize()
        encryptor = self._cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """AES-CBC decryption."""
        decryptor = self._cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = self._padding.unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        return plaintext

    def to_bytes(self) -> bytes:
        """Return initialization vector and key."""
        return self._iv + self._key

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Return AESKey object.

        key_bytes == iv + key

        """
        iv, key = key_bytes[:16], key_bytes[16:]
        return cls(key, iv)

    @classmethod
    def generate(cls) -> Self:
        """Generate AES key."""
        return cls(random(cls.key_size - 16), random(16))


class AES128Key(AESKey):

    """AES-128 key."""

    name = 'aes128'
    key_size = 32


class AES192Key(AESKey):

    """AES-192 key."""

    name = 'aes192'
    key_size = 40


class AES256Key(AESKey):

    """AES-256 key."""

    name = 'aes256'
    key_size = 48


class AES512Key(AESKey):

    """AES-512 key."""

    name = 'aes512'
    key_size = 80


cipher_algorithms = {
    'aes128': AES128Key,
    'aes192': AES192Key,
    'aes256': AES256Key,
    'aes512': AES512Key,
    'none': NoCipher,
}

algorithms = {
    'aes128',
    'aes192',
    'aes256',
    'aes512',
    'none'
}


def get_cipher(algorithm: str) -> type[SymmetricKey]:
    """Get symmetric key class."""
    if cipher := cipher_algorithms.get(algorithm.lower()):
        return cipher
    raise AlgorithmError("Unsupported symmetric encryption algorithm")
