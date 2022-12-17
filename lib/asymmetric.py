#!/usr/bin/python
# Copyright (c) 2022 SiumLhahah
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

""""
ilfocore.lib.asymmetric

Provides key exchange support for ilfocore.

Example

>>> alg = 'x25519'  # or 'rsa4096-sha256'
>>> sk1 = get_client_exchange(alg).generate()
>>> pk1 = sk1.public_bytes()
>>> sk2 = get_server_exchange(alg).generate()
>>> k2, pk2 = sk2.exchange(pk1)
>>> k1 = sk1.exchange(pk2)
>>> k1 == k2
True

"""

from abc import ABCMeta, abstractmethod
from secrets import token_bytes as random
from typing import Self
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    x25519,
    x448,
    rsa,
    padding
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key
)
from .exceptions import AlgorithmError

SharedBytes = bytes
SendBytes = bytes
RecvBytes = bytes


class AsymmetricSecret(metaclass=ABCMeta):

    """Asymmetric secret key."""

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
    @property
    @abstractmethod
    def name(cls) -> str:
        """Algorithm name."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Load key from bytes."""

    @classmethod
    @abstractmethod
    def generate(cls) -> Self:
        """Generate a new key."""


class ClientSecret(AsymmetricSecret):

    """Client secret key."""

    @abstractmethod
    def exchange(self, recv_bytes: RecvBytes) -> SharedBytes:
        """Key exchange."""

    @abstractmethod
    def public_bytes(self) -> SendBytes:
        """Get public bytes."""


class ServerSecret(AsymmetricSecret):

    """Server secret key."""

    @abstractmethod
    def exchange(self, recv_bytes: RecvBytes) -> tuple[SharedBytes,
                                                       SendBytes]:
        """Key exchange."""


class ClientNoSecret(ClientSecret):

    """Client NoSecret.

    Do nothing.

    """

    name = 'none'

    def exchange(self, recv_bytes: RecvBytes) -> SharedBytes:
        """Return received key."""
        return recv_bytes

    def public_bytes(self) -> SendBytes:
        """Return the empty key."""
        return self._key

    def to_bytes(self) -> bytes:
        """Return the key."""
        return self._key

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Return ClientNoSecret object."""
        return cls(secret_bytes)

    @classmethod
    def generate(cls) -> Self:
        """Generate an empty key."""
        return cls(b'')


class ServerNoSecret(ServerSecret):

    """Server NoSecret.

    Generate random bytes and send the plaintext.

    """

    name = 'none'

    def exchange(self, recv_bytes: RecvBytes) -> tuple[SharedBytes,
                                                       SendBytes]:
        """Return plaintext."""
        key = self._key
        return key, key

    def to_bytes(self) -> bytes:
        """Return the key."""
        return self._key

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Return ServerNoSecret object."""
        return cls(secret_bytes)

    @classmethod
    def generate(cls) -> Self:
        """Generate shared key."""
        return cls(random(32))


class X25519Secret(AsymmetricSecret):

    """X25519 private key."""

    name = 'x25519'

    def exchange(self, recv_bytes: RecvBytes) -> SharedBytes:
        """X25519 key exchange."""
        recv_key = x25519.X25519PublicKey.from_public_bytes(recv_bytes)
        return self._key.exchange(recv_key)

    def public_bytes(self) -> SendBytes:
        """Get serialized X25519 public key."""
        send_key = self._key.public_key()
        return send_key.public_bytes(
            Encoding.Raw,
            PublicFormat.Raw
        )

    def to_bytes(self) -> bytes:
        """Serialize X25519 private key to bytes."""
        return self._key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Load X25519 private key from bytes."""
        return cls(x25519.X25519PrivateKey.from_private_bytes(secret_bytes))

    @classmethod
    def generate(cls) -> Self:
        """Generate X25519 private key."""
        return cls(x25519.X25519PrivateKey.generate())


class ClientX25519(X25519Secret, ClientSecret):

    """Client X25519 private key."""


class ServerX25519(X25519Secret, ServerSecret):

    """Client X25519 private key."""

    def exchange(self, recv_bytes: RecvBytes) -> tuple[SharedBytes,
                                                       SendBytes]:
        """X25519 key exchange and get public bytes."""
        return super().exchange(recv_bytes), self.public_bytes()


class X448Secret(AsymmetricSecret):

    """X448 private key."""

    name = 'x448'

    def exchange(self, recv_bytes: RecvBytes) -> SharedBytes:
        """X448 key exchange."""
        recv_key = x448.X448PublicKey.from_public_bytes(recv_bytes)
        return self._key.exchange(recv_key)

    def public_bytes(self) -> SendBytes:
        """Get serialized X448 public key."""
        send_key = self._key.public_key()
        return send_key.public_bytes(
            Encoding.Raw,
            PublicFormat.Raw
        )

    def to_bytes(self) -> bytes:
        """Serialize X448 private key to bytes."""
        return self._key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption()
        )

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Load X448 private key from bytes."""
        return cls(x448.X448PrivateKey.from_private_bytes(secret_bytes))

    @classmethod
    def generate(cls) -> Self:
        """Generate X448 private key."""
        return cls(x448.X448PrivateKey.generate())


class ClientX448(X448Secret, ClientSecret):

    """Client X448 private key."""


class ServerX448(X448Secret, ServerSecret):

    """Client X448 private key."""

    def exchange(self, recv_bytes: RecvBytes) -> tuple[SharedBytes,
                                                       SendBytes]:
        """X448 key exchange and get public bytes."""
        return super().exchange(recv_bytes), self.public_bytes()


class ClientRSA_SHA256(ServerSecret):

    """Client RSA private key."""

    name = 'rsa4096-sha256'

    def __init__(self, key: rsa.RSAPrivateKey):
        super().__init__(key)
        self.name += str(key.key_bits)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """RSA decryption."""
        plaintext = self._key.decrypt(
            ciphertext,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                None
            )
        )
        return plaintext

    def exchange(self, recv_bytes: RecvBytes) -> SharedBytes:
        """RSA key exchange."""
        return self.decrypt(recv_bytes)

    def public_bytes(self) -> SendBytes:
        """Get serialized RSA public key."""
        send_key = self._key.public_key()
        return send_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo
        )

    def to_bytes(self) -> bytes:
        """Serialize RSA private key to bytes."""
        return self._key.private_key.private_bytes(
            Encoding.DER,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption()
        )

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Load RSA private key from bytes."""
        return cls(load_der_private_key(secret_bytes, None))

    @classmethod
    def generate(cls) -> Self:
        """Generate RSA private key."""
        return cls(rsa.generate_private_key(65537, cls.key_bits))

    @classmethod
    @property
    @abstractmethod
    def key_bits(cls) -> int:
        """RSA key bit length."""


class ClientRSA4096_SHA256(ClientRSA_SHA256):

    """Client RSA-4096 private key."""

    key_bits = 4096


class ServerRSA_SHA256(ServerSecret):

    """Server secret, exchanged with RSA public key."""

    name = 'rsa4096-sha256'

    def __init__(self, key: bytes):
        super().__init__(None)
        self._shared_key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """RSA encryption."""
        ciphertext = self._key.encrypt(
            plaintext,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                None
            )
        )
        return ciphertext

    def exchange(self, recv_bytes: RecvBytes) -> tuple[SharedBytes,
                                                       SendBytes]:
        """Return shared key and encrypted shared key."""
        self._key = load_der_public_key(recv_bytes)
        self.name += str(self._key.key_bits)
        shared_key = self._shared_key
        return shared_key, self.encrypt(shared_key)

    def to_bytes(self) -> bytes:
        """Return shared key."""
        return self._shared_key

    @classmethod
    def from_bytes(cls, secret_bytes: bytes) -> Self:
        """Return ServerSecret object from shared key."""
        return cls(secret_bytes)

    @classmethod
    def generate(cls) -> Self:
        """Generate shared key."""
        return cls(random(32))


client_exchange_algorithms = {
    'x25519': ClientX25519,
    'x448': ClientX448,
    'rsa4096-sha256': ClientRSA4096_SHA256,
    'none': ClientNoSecret,
}

server_exchange_algorithms = {
    'x25519': ServerX25519,
    'x448': ServerX448,
    'rsa4096-sha256': ServerRSA_SHA256,
    'none': ServerNoSecret
}

algorithms = {
    'x25519',
    'rsa4096-sha256',
    'none'
}


def get_client_exchange(algorithm: str) -> type[ClientSecret]:
    """Get key exchange class."""
    if exchange := client_exchange_algorithms.get(algorithm.lower()):
        return exchange
    raise AlgorithmError("Unsupported key exchange algorithm")


def get_server_exchange(algorithm: str) -> type[ServerSecret]:
    """Get key exchange class."""
    if exchange := server_exchange_algorithms.get(algorithm.lower()):
        return exchange
    raise AlgorithmError("Unsupported key exchange algorithm")
