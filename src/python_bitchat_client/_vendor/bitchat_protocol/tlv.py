"""
TLV (Type-Length-Value) codec for BitChat announcement and private message packets.

Format: [Type:1][Length:1][Value:n] — max 255 bytes per value.

AnnouncementPacket TLV types:
  0x01 = nickname (UTF-8)
  0x02 = noisePublicKey (32 bytes Curve25519)
  0x03 = signingPublicKey (32 bytes Ed25519)
  0x04 = directNeighbors (multiples of 8 bytes, up to 10 neighbors)

PrivateMessagePacket TLV types:
  0x00 = messageID (UTF-8)
  0x01 = content (UTF-8)

AnnouncementPacket decoder is lenient: unknown tags are skipped.
PrivateMessagePacket decoder is strict: unknown tags return None.
"""

from __future__ import annotations

from typing import Optional

from .errors import TLVDecodeError, TLVEncodeError
from .types import AnnouncementPacket, PrivateMessagePacket

# ── AnnouncementPacket tag constants ─────────────────────────────────────────
_ANN_NICKNAME = 0x01
_ANN_NOISE_KEY = 0x02
_ANN_SIGNING_KEY = 0x03
_ANN_NEIGHBORS = 0x04

# ── PrivateMessagePacket tag constants ────────────────────────────────────────
_PM_MESSAGE_ID = 0x00
_PM_CONTENT = 0x01


def encode_announcement(packet: AnnouncementPacket) -> bytes:
    """Encode an AnnouncementPacket to TLV bytes."""
    nickname_bytes = packet.nickname.encode("utf-8")
    if len(nickname_bytes) > 255:
        raise TLVEncodeError("nickname too long (max 255 bytes UTF-8)")
    if len(packet.noise_public_key) > 255:
        raise TLVEncodeError("noise_public_key too long")
    if len(packet.signing_public_key) > 255:
        raise TLVEncodeError("signing_public_key too long")

    out = bytearray()
    out.extend(_make_tlv(_ANN_NICKNAME, nickname_bytes))
    out.extend(_make_tlv(_ANN_NOISE_KEY, packet.noise_public_key))
    out.extend(_make_tlv(_ANN_SIGNING_KEY, packet.signing_public_key))

    if packet.direct_neighbors:
        neighbors = packet.direct_neighbors[:10]
        neighbor_data = b"".join(neighbors)
        if neighbor_data and len(neighbor_data) % 8 == 0 and len(neighbor_data) <= 255:
            out.extend(_make_tlv(_ANN_NEIGHBORS, neighbor_data))

    return bytes(out)


def decode_announcement(data: bytes) -> Optional[AnnouncementPacket]:
    """Decode TLV bytes into an AnnouncementPacket. Returns None on failure."""
    offset = 0
    nickname: Optional[str] = None
    noise_public_key: Optional[bytes] = None
    signing_public_key: Optional[bytes] = None
    direct_neighbors: Optional[list[bytes]] = None

    while offset + 2 <= len(data):
        tag = data[offset]; offset += 1
        length = data[offset]; offset += 1
        if offset + length > len(data):
            return None
        value = data[offset:offset + length]; offset += length

        if tag == _ANN_NICKNAME:
            try:
                nickname = value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        elif tag == _ANN_NOISE_KEY:
            noise_public_key = bytes(value)
        elif tag == _ANN_SIGNING_KEY:
            signing_public_key = bytes(value)
        elif tag == _ANN_NEIGHBORS:
            if length > 0 and length % 8 == 0:
                count = length // 8
                direct_neighbors = [value[i * 8:(i + 1) * 8] for i in range(count)]
        else:
            pass  # Unknown tag — skip (forward-compatible)

    if nickname is None or noise_public_key is None or signing_public_key is None:
        return None

    return AnnouncementPacket(
        nickname=nickname,
        noise_public_key=noise_public_key,
        signing_public_key=signing_public_key,
        direct_neighbors=direct_neighbors,
    )


def encode_private_message(packet: PrivateMessagePacket) -> bytes:
    """Encode a PrivateMessagePacket to TLV bytes."""
    message_id_bytes = packet.message_id.encode("utf-8")
    content_bytes = packet.content.encode("utf-8")
    if len(message_id_bytes) > 255:
        raise TLVEncodeError("message_id too long (max 255 bytes UTF-8)")
    if len(content_bytes) > 255:
        raise TLVEncodeError("content too long (max 255 bytes UTF-8)")

    out = bytearray()
    out.extend(_make_tlv(_PM_MESSAGE_ID, message_id_bytes))
    out.extend(_make_tlv(_PM_CONTENT, content_bytes))
    return bytes(out)


def decode_private_message(data: bytes) -> Optional[PrivateMessagePacket]:
    """Decode TLV bytes into a PrivateMessagePacket.

    Returns None on failure or unknown tags (strict decoder).
    """
    offset = 0
    message_id: Optional[str] = None
    content: Optional[str] = None

    while offset + 2 <= len(data):
        tag = data[offset]; offset += 1
        if tag not in (_PM_MESSAGE_ID, _PM_CONTENT):
            return None  # Strict: unknown tag → failure
        length = data[offset]; offset += 1
        if offset + length > len(data):
            return None
        value = data[offset:offset + length]; offset += length

        try:
            if tag == _PM_MESSAGE_ID:
                message_id = value.decode("utf-8")
            else:
                content = value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    if message_id is None or content is None:
        return None

    return PrivateMessagePacket(message_id=message_id, content=content)


def _make_tlv(tag: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise TLVEncodeError(f"TLV value too long for tag 0x{tag:02x}: {len(value)} bytes")
    return bytes([tag, len(value)]) + value
