"""
PeerID utilities for the BitChat protocol.

Peer IDs are derived from Noise static public keys:
  Short form (8 bytes): first 8 bytes of SHA-256(noisePublicKey) = 16 lowercase hex chars

Nostr-backed variants:
  GeoDM:    "nostr_" + nostrPubkey[:16]
  GeoChat:  "nostr:" + nostrPubkey[:8]
"""

from __future__ import annotations

import hashlib


def peer_id_from_noise_key(noise_public_key: bytes) -> str:
    """Derive a short peer ID from a 32-byte Noise static public key.

    Matches Swift: SHA256(noisePublicKey).hexString.prefix(16)

    Args:
        noise_public_key: 32-byte Curve25519 public key.

    Returns:
        16-char lowercase hex peer ID.
    """
    digest = hashlib.sha256(noise_public_key).digest()
    return digest[:8].hex()


def peer_id_to_bytes(peer_id: str) -> bytes:
    """Convert a peer ID hex string to its 8-byte binary representation.

    Raises:
        ValueError: if the hex string is not exactly 16 lowercase hex characters.
    """
    if len(peer_id) != 16 or not all(c in "0123456789abcdef" for c in peer_id):
        raise ValueError(f"Invalid peer ID: '{peer_id}' (expected 16 hex chars)")
    return bytes.fromhex(peer_id)


def peer_id_from_bytes(data: bytes) -> str:
    """Convert 8 bytes to a peer ID hex string.

    Raises:
        ValueError: if the buffer is shorter than 8 bytes.
    """
    if len(data) < 8:
        raise ValueError(f"Peer ID buffer too short: {len(data)} bytes")
    return data[:8].hex()


def nostr_geo_dm_peer_id(nostr_pubkey_hex: str) -> str:
    """Derive a Nostr-backed peer ID for GeoDM messages.
    Format: "nostr_" + nostrPubkey[:16]
    """
    return "nostr_" + nostr_pubkey_hex[:16]


def nostr_geo_chat_peer_id(nostr_pubkey_hex: str) -> str:
    """Derive a Nostr-backed peer ID for GeoChat (public channel) messages.
    Format: "nostr:" + nostrPubkey[:8]
    """
    return "nostr:" + nostr_pubkey_hex[:8]
