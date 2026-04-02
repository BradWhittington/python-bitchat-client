import hashlib
import hmac
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class NoiseRole(StrEnum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


class NoiseCipherState:
    def __init__(self, *, use_extracted_nonce: bool = False) -> None:
        self._key: bytes | None = None
        self._nonce = 0
        self._use_extracted_nonce = use_extracted_nonce

    def initialize_key(self, key: bytes) -> None:
        self._key = key
        self._nonce = 0

    def has_key(self) -> bool:
        return self._key is not None

    @staticmethod
    def _nonce12(nonce: int) -> bytes:
        return b"\x00\x00\x00\x00" + int(nonce).to_bytes(8, "little")

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        if self._key is None:
            raise ValueError("cipher not initialized")
        current_nonce = self._nonce
        cipher = ChaCha20Poly1305(self._key)
        ciphertext = cipher.encrypt(
            nonce=self._nonce12(current_nonce),
            data=plaintext,
            associated_data=associated_data,
        )
        self._nonce += 1
        if self._use_extracted_nonce:
            nonce4 = (current_nonce & 0xFFFFFFFF).to_bytes(4, "big")
            return nonce4 + ciphertext
        return ciphertext

    def decrypt(self, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        if self._key is None:
            raise ValueError("cipher not initialized")
        nonce = self._nonce
        body = ciphertext
        if self._use_extracted_nonce:
            if len(ciphertext) < 5:
                raise ValueError("invalid ciphertext")
            nonce = int.from_bytes(ciphertext[:4], "big")
            body = ciphertext[4:]
        cipher = ChaCha20Poly1305(self._key)
        plaintext = cipher.decrypt(
            nonce=self._nonce12(nonce),
            data=body,
            associated_data=associated_data,
        )
        self._nonce = max(self._nonce + 1, nonce + 1)
        return plaintext


class NoiseSymmetricState:
    def __init__(self, protocol_name: str) -> None:
        name = protocol_name.encode("utf-8")
        if len(name) <= 32:
            self._hash = name + b"\x00" * (32 - len(name))
        else:
            self._hash = hashlib.sha256(name).digest()
        self._chaining_key = self._hash
        self._cipher = NoiseCipherState()

    def mix_hash(self, data: bytes) -> None:
        self._hash = hashlib.sha256(self._hash + data).digest()

    def _hkdf(self, ikm: bytes, n: int) -> list[bytes]:
        temp_key = hmac.new(self._chaining_key, ikm, hashlib.sha256).digest()
        out: list[bytes] = []
        prev = b""
        for i in range(1, n + 1):
            prev = hmac.new(temp_key, prev + bytes([i]), hashlib.sha256).digest()
            out.append(prev)
        return out

    def mix_key(self, ikm: bytes) -> None:
        ck, temp_k = self._hkdf(ikm, 2)
        self._chaining_key = ck
        self._cipher.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._cipher.has_key():
            ct = self._cipher.encrypt(plaintext, self._hash)
            self.mix_hash(ct)
            return ct
        self.mix_hash(plaintext)
        return plaintext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._cipher.has_key():
            pt = self._cipher.decrypt(ciphertext, self._hash)
            self.mix_hash(ciphertext)
            return pt
        self.mix_hash(ciphertext)
        return ciphertext

    def split(
        self, *, use_extracted_nonce: bool
    ) -> tuple[NoiseCipherState, NoiseCipherState]:
        k1, k2 = self._hkdf(b"", 2)
        c1 = NoiseCipherState(use_extracted_nonce=use_extracted_nonce)
        c2 = NoiseCipherState(use_extracted_nonce=use_extracted_nonce)
        c1.initialize_key(k1)
        c2.initialize_key(k2)
        return c1, c2

    @property
    def handshake_hash(self) -> bytes:
        return self._hash

    def has_cipher_key(self) -> bool:
        return self._cipher.has_key()


class NoiseHandshakeState:
    def __init__(self, *, role: NoiseRole, local_static: X25519PrivateKey) -> None:
        self._role = role
        self._symmetric = NoiseSymmetricState("Noise_XX_25519_ChaChaPoly_SHA256")
        # Match iOS NoiseHandshakeState initialization semantics:
        # mixHash(prologue) is always called, even when prologue is empty.
        # This updates h := SHA256(h || "") and is required for transcript parity.
        self._symmetric.mix_hash(b"")
        self._current_pattern = 0
        self._local_static_private = local_static
        self._local_static_public = local_static.public_key()
        self._local_ephemeral_private: X25519PrivateKey | None = None
        self._local_ephemeral_public: X25519PublicKey | None = None
        self._remote_static_public: X25519PublicKey | None = None
        self._remote_ephemeral_public: X25519PublicKey | None = None

    def _perform_dh(self, left: X25519PrivateKey, right: X25519PublicKey) -> None:
        shared = left.exchange(right)
        self._symmetric.mix_key(shared)

    @staticmethod
    def _require(value, name: str):
        if value is None:
            raise ValueError(f"missing key for {name}")
        return value

    def write_message(self, payload: bytes = b"") -> bytes:
        patterns = [["e"], ["e", "ee", "s", "es"], ["s", "se"]]
        if self._current_pattern >= len(patterns):
            raise ValueError("handshake complete")
        out = bytearray()
        for token in patterns[self._current_pattern]:
            if token == "e":
                local_ephemeral_private = X25519PrivateKey.generate()
                local_ephemeral_public = local_ephemeral_private.public_key()
                self._local_ephemeral_private = local_ephemeral_private
                self._local_ephemeral_public = local_ephemeral_public
                e_bytes = local_ephemeral_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw,
                )
                out.extend(e_bytes)
                self._symmetric.mix_hash(e_bytes)
            elif token == "s":
                s_bytes = self._local_static_public.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw,
                )
                out.extend(self._symmetric.encrypt_and_hash(s_bytes))
            elif token == "ee":
                self._perform_dh(
                    self._require(self._local_ephemeral_private, "ee local e"),
                    self._require(self._remote_ephemeral_public, "ee remote e"),
                )
            elif token == "es":
                if self._role == NoiseRole.INITIATOR:
                    self._perform_dh(
                        self._require(self._local_ephemeral_private, "es local e"),
                        self._require(self._remote_static_public, "es remote s"),
                    )
                else:
                    self._perform_dh(
                        self._local_static_private,
                        self._require(self._remote_ephemeral_public, "es remote e"),
                    )
            elif token == "se":
                if self._role == NoiseRole.INITIATOR:
                    self._perform_dh(
                        self._local_static_private,
                        self._require(self._remote_ephemeral_public, "se remote e"),
                    )
                else:
                    self._perform_dh(
                        self._require(self._local_ephemeral_private, "se local e"),
                        self._require(self._remote_static_public, "se remote s"),
                    )
        out.extend(self._symmetric.encrypt_and_hash(payload))
        self._current_pattern += 1
        return bytes(out)

    def read_message(self, message: bytes) -> bytes:
        patterns = [["e"], ["e", "ee", "s", "es"], ["s", "se"]]
        if self._current_pattern >= len(patterns):
            raise ValueError("handshake complete")
        buf = memoryview(message)
        for token in patterns[self._current_pattern]:
            if token == "e":
                if len(buf) < 32:
                    raise ValueError("invalid handshake message")
                e = bytes(buf[:32])
                self._remote_ephemeral_public = X25519PublicKey.from_public_bytes(e)
                self._symmetric.mix_hash(e)
                buf = buf[32:]
            elif token == "s":
                key_len = 48 if self._symmetric.has_cipher_key() else 32
                if len(buf) < key_len:
                    raise ValueError("invalid handshake message")
                encrypted_s = bytes(buf[:key_len])
                s = self._symmetric.decrypt_and_hash(encrypted_s)
                self._remote_static_public = X25519PublicKey.from_public_bytes(s)
                buf = buf[key_len:]
            elif token == "ee":
                self._perform_dh(
                    self._require(self._local_ephemeral_private, "ee local e"),
                    self._require(self._remote_ephemeral_public, "ee remote e"),
                )
            elif token == "es":
                if self._role == NoiseRole.INITIATOR:
                    self._perform_dh(
                        self._require(self._local_ephemeral_private, "es local e"),
                        self._require(self._remote_static_public, "es remote s"),
                    )
                else:
                    self._perform_dh(
                        self._local_static_private,
                        self._require(self._remote_ephemeral_public, "es remote e"),
                    )
            elif token == "se":
                if self._role == NoiseRole.INITIATOR:
                    self._perform_dh(
                        self._local_static_private,
                        self._require(self._remote_ephemeral_public, "se remote e"),
                    )
                else:
                    self._perform_dh(
                        self._require(self._local_ephemeral_private, "se local e"),
                        self._require(self._remote_static_public, "se remote s"),
                    )
        payload = self._symmetric.decrypt_and_hash(bytes(buf))
        self._current_pattern += 1
        return payload

    def is_complete(self) -> bool:
        return self._current_pattern >= 3

    def handshake_hash(self) -> bytes:
        return self._symmetric.handshake_hash

    def get_transport_ciphers(self) -> tuple[NoiseCipherState, NoiseCipherState]:
        if not self.is_complete():
            raise ValueError("handshake not complete")
        c1, c2 = self._symmetric.split(use_extracted_nonce=True)
        if self._role == NoiseRole.INITIATOR:
            return c1, c2
        return c2, c1

    @property
    def remote_static_public_key(self) -> bytes | None:
        if self._remote_static_public is None:
            return None
        return self._remote_static_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
