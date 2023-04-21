""""
ilfocore.lib.signature

Provides signature support for ilfocore.

Example

>>> alg = 'ed25519'
>>> msg = b'a message'
>>> sk = get_sign(alg).generate()
>>> sig = sk.sign(msg)
>>> pk_bytes = sk.public_key.to_bytes()
>>> pk = get_verify(alg).from_bytes(pk_bytes)
>>> pk.verify(sig, msg)

"""

from abc import ABCMeta, abstractmethod
from typing import Self
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    ed448,
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


class SignatureKey(metaclass=ABCMeta):

    """Key for signature, to sign or to verify."""

    def __init__(self, key: object):
        self._key = key

    @property
    def key(self) -> object:
        """Return the key."""
        return self._key

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Dump the key to bytes."""

    @classmethod
    @property
    @abstractmethod
    def name(cls) -> str:
        """Algorithm name."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load key from bytes."""


class PublicKey(SignatureKey):

    """Key to verify."""

    @abstractmethod
    def verify(self, signature: bytes, data: bytes):
        """Verify the signature."""


class PrivateKey(SignatureKey):

    """Key to sign."""

    def __init__(self, pub_key: PublicKey, priv_key: object):
        self._pub_key = pub_key
        super().__init__(priv_key)

    @property
    def public_key(self) -> PublicKey:
        """Get public key."""
        return self._pub_key

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign the data."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, priv_bytes: bytes,
                   pub_bytes: bytes | None = None) -> Self:
        """Load keys from bytes."""

    @classmethod
    @abstractmethod
    def generate(cls) -> Self:
        """Generate a new key."""


class NoSignatureKey(SignatureKey):
    # pylint: disable=W0223
    """No key for signature."""

    name = 'none'

    def to_bytes(self) -> bytes:
        """Return the key."""
        return self._key


class NoVerifyKey(NoSignatureKey, PublicKey):

    """No key to verify."""

    def verify(self, signature: bytes, data: bytes):
        """Does nothing."""

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Return NoVerifyKey object."""
        return cls(key_bytes)


class NoSignKey(NoSignatureKey, PrivateKey):

    """No key to sign."""

    def sign(self, data: bytes) -> bytes:
        """Return empty bytes."""
        return b''

    @classmethod
    def from_bytes(cls, priv_bytes: bytes,
                   pub_bytes: bytes | None = None) -> Self:
        """Return NoSignKey object."""
        if pub_bytes is None:
            pub_bytes = b''
        return cls(NoVerifyKey(pub_bytes), priv_bytes)

    @classmethod
    def generate(cls) -> Self:
        """Generate an empty key."""
        return cls(NoVerifyKey(b''), b'')


class Ed25519PublicKey(PublicKey):

    """Ed25519 public key."""

    name = 'ed25519'

    def __init__(self, key, pub_bytes=None):
        super().__init__(key)
        if pub_bytes is None:
            self._pub_bytes = self._key.public_bytes(
                Encoding.Raw,
                PublicFormat.Raw
            )
        else:
            self._pub_bytes = pub_bytes

    def verify(self, signature: bytes, data: bytes):
        """Verify the signature."""
        try:
            self._key.verify(signature, data)
        except Exception:
            raise ValueError

    def to_bytes(self) -> bytes:
        """Dump the Ed25519 public key to bytes."""
        return self._pub_bytes

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load Ed25519 public key from bytes."""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception:
            raise ValueError
        return cls(key, key_bytes)


class Ed25519PrivateKey(PrivateKey):

    """Ed25519 private key."""

    name = 'ed25519'

    def __init__(self, pub_key, priv_key, priv_bytes=None):
        super().__init__(pub_key, priv_key)
        if priv_bytes is None:
            self._priv_bytes = self._key.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption()
            )
        else:
            self._priv_bytes = priv_bytes

    def sign(self, data: bytes) -> bytes:
        """Sign the data."""
        return self._key.sign(data)

    def to_bytes(self) -> bytes:
        """Dump the Ed25519 private key to bytes."""
        return self._priv_bytes

    @classmethod
    def from_bytes(cls, priv_bytes: bytes,
                   pub_bytes: bytes | None = None) -> Self:
        """Load Ed25519 key pair from bytes."""
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        if pub_bytes is None:
            pub_key = Ed25519PublicKey(priv_key.public_key())
        else:
            pub_key = Ed25519PublicKey.from_bytes(pub_bytes)
        return cls(pub_key, priv_key, priv_bytes)

    @classmethod
    def generate(cls):
        """Generate a new Ed25519 key."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = Ed25519PublicKey(priv_key.public_key())
        return cls(pub_key, priv_key)


class Ed448PublicKey(PublicKey):

    """Ed448 public key."""

    name = 'ed448'

    def __init__(self, key, pub_bytes=None):
        super().__init__(key)
        if pub_bytes is None:
            self._pub_bytes = self._key.public_bytes(
                Encoding.Raw,
                PublicFormat.Raw
            )
        else:
            self._pub_bytes = pub_bytes

    def verify(self, signature: bytes, data: bytes):
        """Verify the signature."""
        try:
            self._key.verify(signature, data)
        except Exception:
            raise ValueError

    def to_bytes(self) -> bytes:
        """Dump the Ed448 public key to bytes."""
        return self._pub_bytes

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load Ed448 public key from bytes."""
        try:
            key = ed448.Ed448PublicKey.from_public_bytes(key_bytes)
        except Exception:
            raise ValueError
        return cls(key, key_bytes)


class Ed448PrivateKey(PrivateKey):

    """Ed448 private key."""

    name = 'ed448'

    def __init__(self, pub_key, priv_key, priv_bytes=None):
        super().__init__(pub_key, priv_key)
        if priv_bytes is None:
            self._priv_bytes = self._key.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption()
            )
        else:
            self._priv_bytes = priv_bytes

    def sign(self, data: bytes) -> bytes:
        """Sign the data."""
        return self._key.sign(data)

    def to_bytes(self) -> bytes:
        """Dump the Ed448 private key to bytes."""
        return self._priv_bytes

    @classmethod
    def from_bytes(cls, priv_bytes: bytes,
                   pub_bytes: bytes | None = None) -> Self:
        """Load Ed448 private key from bytes."""
        priv_key = ed448.Ed448PrivateKey.from_private_bytes(priv_bytes)
        if pub_bytes is None:
            pub_key = Ed448PublicKey(priv_key.public_key())
        else:
            pub_key = Ed448PublicKey.from_bytes(pub_bytes)
        return cls(pub_key, priv_key, priv_bytes)

    @classmethod
    def generate(cls):
        """Generate a new Ed448 private key."""
        priv_key = ed448.Ed448PrivateKey.generate()
        pub_key = Ed448PublicKey(priv_key.public_key())
        return cls(pub_key, priv_key)


class RSAPublicKeySHA256(PublicKey):

    """RSA public key."""

    name = 'rsa-sha256'

    def __init__(self, key, pub_bytes=None):
        super().__init__(key)
        if pub_bytes is None:
            self._pub_bytes = self._key.public_bytes(
                Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo
            )
        else:
            self._pub_bytes = pub_bytes

    def verify(self, signature: bytes, data: bytes):
        """Verify the signature."""
        try:
            self._key.verify(
                signature,
                data,
                padding.PSS(
                    padding.MGF1(hashes.SHA256()),
                    padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception:
            raise ValueError

    def to_bytes(self) -> bytes:
        """Dump the RSA public key to bytes."""
        return self._pub_bytes

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> Self:
        """Load RSA public key from bytes."""
        return cls(load_der_public_key(key_bytes), key_bytes)


class RSAPrivateKeySHA256(PrivateKey):

    """RSA private key."""

    name = 'rsa-sha256'

    def __init__(self, pub_key, priv_key, priv_bytes=None):
        super().__init__(pub_key, priv_key)
        if priv_bytes is None:
            self._priv_bytes = self._key.private_bytes(
                Encoding.DER,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption()
            )
        else:
            self._priv_bytes = priv_bytes

    def sign(self, data: bytes) -> bytes:
        """Sign the data."""
        return self._key.sign(
            data,
            padding.PSS(
                padding.MGF1(hashes.SHA256()),
                padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def to_bytes(self) -> bytes:
        """Dump the RSA private key to bytes."""
        return self._priv_bytes

    @classmethod
    def from_bytes(cls, priv_bytes: bytes,
                   pub_bytes: bytes | None = None) -> Self:
        """Load RSA private key from bytes."""
        priv_key = load_der_private_key(priv_bytes, None)
        if pub_bytes is None:
            pub_key = RSAPublicKeySHA256(priv_key.public_key())
        else:
            pub_key = RSAPublicKeySHA256.from_bytes(pub_bytes)
        return cls(pub_key, priv_key, priv_bytes)

    @classmethod
    def generate(cls, key_size=4096):
        """Generate a new RSA private key."""
        priv_key = rsa.generate_private_key(65537, key_size)
        pub_key = RSAPublicKeySHA256(priv_key.public_key())
        return cls(pub_key, priv_key)


sign_algorithms = {
    'ed25519': Ed25519PrivateKey,
    'ed448': Ed448PrivateKey,
    'rsa-sha256': RSAPrivateKeySHA256,
    'none': NoSignKey
}

verify_algorithms = {
    'ed25519': Ed25519PublicKey,
    'ed448': Ed448PublicKey,
    'rsa-sha256': RSAPublicKeySHA256,
    'none': NoVerifyKey
}

algorithms = {
    'ed25519',
    'ed448',
    'rsa-sha256',
    'none'
}


def get_sign(algorithm: str) -> type[PrivateKey]:
    """Get signing class."""
    if sign := sign_algorithms.get(algorithm.lower()):
        return sign
    raise AlgorithmError("Unsupported signature algorithm")


def get_verify(algorithm: str) -> type[PublicKey]:
    """Get verifying class."""
    if verify := verify_algorithms.get(algorithm.lower()):
        return verify
    raise AlgorithmError("Unsupported signature algorithm")
