"""
Core types for the BitChat binary protocol.

These mirror the wire-format structures from BinaryProtocol.swift.
"""

from __future__ import annotations

import dataclasses
from enum import IntEnum
from typing import Optional


class MessageType(IntEnum):
    """Application-layer message types (outer packet type byte)."""
    ANNOUNCE = 0x01          # Peer announcement — broadcasts nickname and public keys.
    MESSAGE = 0x02           # Public broadcast chat message.
    LEAVE = 0x03             # Peer departure notification.
    NOISE_HANDSHAKE = 0x10   # Noise Protocol handshake (init or response).
    NOISE_ENCRYPTED = 0x11   # Noise-encrypted payload — all private messages, receipts, etc.
    FRAGMENT = 0x20          # Fragment of a multi-part large message.
    REQUEST_SYNC = 0x21      # Gossip sync request.
    FILE_TRANSFER = 0x22     # Binary file / audio / image payload.


class NoisePayloadType(IntEnum):
    """Payload type — first byte inside a decrypted NoiseEncrypted payload."""
    PRIVATE_MESSAGE = 0x01   # Private chat message.
    READ_RECEIPT = 0x02      # Read receipt (message was read by recipient).
    DELIVERED = 0x03         # Delivery confirmation (message reached device).
    FILE_TRANSFER = 0x20     # In-band file transfer.
    VERIFY_CHALLENGE = 0x10  # OOB verification challenge.
    VERIFY_RESPONSE = 0x11   # OOB verification response.


class PacketFlag(IntEnum):
    """Bit flags in the header flags byte."""
    HAS_RECIPIENT = 0x01   # Packet has a RecipientID field (directed message).
    HAS_SIGNATURE = 0x02   # Packet has a 64-byte Ed25519 signature appended.
    IS_COMPRESSED = 0x04   # Payload is zlib-compressed.
    HAS_ROUTE = 0x08       # Source route list (v2+ only).
    IS_RSR = 0x10          # Relay-Sync-Request.


@dataclasses.dataclass
class BitchatPacket:
    """A decoded BitChat protocol packet.

    All binary fields use `bytes`. `timestamp` is in milliseconds since Unix epoch.
    """
    version: int             # Wire format version (1 or 2).
    type: int                # Message type byte. See MessageType.
    ttl: int                 # Time-to-live hop limit.
    timestamp: int           # Timestamp in milliseconds since Unix epoch.
    flags: int               # Flags byte. See PacketFlag.
    sender_id: bytes         # Sender peer ID — 8 bytes.
    payload: bytes           # Decoded (decompressed if applicable) payload bytes.
    recipient_id: Optional[bytes] = None   # Recipient peer ID — 8 bytes (if directed).
    route: Optional[list[bytes]] = None    # Source route hops — each 8 bytes (v2+ only).
    signature: Optional[bytes] = None      # 64-byte Ed25519 signature (if signed).
    is_rsr: bool = False                   # Whether this is a Relay-Sync-Request.

    @property
    def has_recipient(self) -> bool:
        return bool(self.flags & PacketFlag.HAS_RECIPIENT)

    @property
    def has_signature(self) -> bool:
        return bool(self.flags & PacketFlag.HAS_SIGNATURE)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & PacketFlag.IS_COMPRESSED)

    @property
    def has_route(self) -> bool:
        return bool(self.flags & PacketFlag.HAS_ROUTE)


@dataclasses.dataclass
class AnnouncementPacket:
    """TLV-decoded AnnouncementPacket fields."""
    nickname: str                            # Human-readable peer nickname (UTF-8, max 255 bytes).
    noise_public_key: bytes                  # 32-byte Curve25519 noise static public key.
    signing_public_key: bytes                # 32-byte Ed25519 signing public key.
    direct_neighbors: Optional[list[bytes]] = None  # Up to 10 direct BLE neighbor peer IDs (8 bytes each).


@dataclasses.dataclass
class PrivateMessagePacket:
    """TLV-decoded PrivateMessagePacket fields."""
    message_id: str    # Message ID (UTF-8 string).
    content: str       # Message content (UTF-8 string).
