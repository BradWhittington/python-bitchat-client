"""Key management for BitChat identity."""

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey


@dataclass
class IdentityKeyPair:
    """BitChat identity with Noise (Curve25519) and Ed25519 signing keys."""

    noise_private_key: bytes
    signing_private_key: bytes
    noise_public_key: bytes | None = None
    signing_public_key: bytes | None = None

    def __post_init__(self):
        if self.noise_public_key is None:
            private = X25519PrivateKey.from_private_bytes(self.noise_private_key)
            self.noise_public_key = private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        if self.signing_public_key is None:
            signing_key = SigningKey(self.signing_private_key, encoder=RawEncoder)
            self.signing_public_key = signing_key.verify_key._key

    @property
    def peer_id(self) -> str:
        """Derive peer ID from noise public key using SHA-256."""
        return hashlib.sha256(self.noise_public_key).hexdigest()

    @property
    def short_peer_id(self) -> str:
        """Get short peer ID (first 8 bytes/16 hex chars)."""
        return self.peer_id[:16]

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        """Generate new random identity."""
        noise_private = X25519PrivateKey.generate()
        noise_public = noise_private.public_key()

        signing_key = SigningKey.generate()

        return cls(
            noise_private_key=noise_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            noise_public_key=noise_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            signing_private_key=signing_key._seed,
            signing_public_key=signing_key.verify_key._key,
        )

    @classmethod
    def from_seed(cls, seed: bytes) -> "IdentityKeyPair":
        """Generate identity from deterministic seed."""
        noise_seed = hashlib.sha256(seed + b"noise").digest()
        signing_seed = hashlib.sha256(seed + b"signing").digest()

        noise_private = X25519PrivateKey.from_private_bytes(noise_seed)
        noise_public = noise_private.public_key()

        signing_key = SigningKey(signing_seed, encoder=RawEncoder)

        return cls(
            noise_private_key=noise_seed,
            noise_public_key=noise_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            signing_private_key=signing_seed,
            signing_public_key=signing_key.verify_key._key,
        )
