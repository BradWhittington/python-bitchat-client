"""
Binary encode/decode for BitChat protocol packets.

Wire format (all multi-byte fields are big-endian / network byte order):

v1 Header (14 bytes):
  version(1) type(1) ttl(1) timestamp(8) flags(1) payloadLen(2)

v2 Header (16 bytes):
  version(1) type(1) ttl(1) timestamp(8) flags(1) payloadLen(4)

Variable fields (in order):
  senderID(8)
  recipientID(8)          — only when flags & HAS_RECIPIENT
  routeCount(1)           — only when flags & HAS_ROUTE AND version >= 2
  route[0..n](n*8)        — routeCount hops of 8 bytes each
  [originalSize(2 or 4)]  — only when flags & IS_COMPRESSED
  payload(payloadLen - sizeof(originalSize if compressed))
  signature(64)           — only when flags & HAS_SIGNATURE
"""

from __future__ import annotations

import struct
import zlib
from typing import Optional

from .errors import (
    BitchatProtocolError,
    DecompressionError,
    PacketTooShortError,
    SuspiciousCompressionRatioError,
    TruncatedFieldError,
    UnsupportedVersionError,
)
from .types import BitchatPacket, PacketFlag

# Fixed sizes
V1_HEADER_SIZE = 14
V2_HEADER_SIZE = 16
SENDER_ID_SIZE = 8
RECIPIENT_ID_SIZE = 8
SIGNATURE_SIZE = 64
COMPRESSION_THRESHOLD = 256
MAX_COMPRESSION_RATIO = 50_000


def _header_size(version: int) -> int:
    return V2_HEADER_SIZE if version == 2 else V1_HEADER_SIZE


def _len_field_size(version: int) -> int:
    return 4 if version == 2 else 2


def encode(packet: BitchatPacket, *, padding: bool = False) -> bytes:
    """Encode a BitchatPacket to its binary wire representation.

    Args:
        packet:  The packet to encode.
        padding: If True, apply PKCS7-style block padding (for BLE transmission).

    Returns:
        Encoded bytes.

    Raises:
        UnsupportedVersionError: if version is not 1 or 2.
        BitchatProtocolError: on encoding failure.
    """
    version = packet.version
    if version not in (1, 2):
        raise UnsupportedVersionError(version)

    # Compress payload if beneficial
    payload = packet.payload
    is_compressed = False
    original_payload_size = 0

    if len(payload) > COMPRESSION_THRESHOLD:
        _c = zlib.compressobj(level=6, wbits=-15)  # raw deflate
        compressed = _c.compress(payload) + _c.flush()
        if len(compressed) < len(payload):
            original_payload_size = len(payload)
            payload = compressed
            is_compressed = True

    len_field_bytes = _len_field_size(version)

    # Route (v2+ only)
    route: list[bytes] = packet.route if version >= 2 and packet.route else []
    has_route = len(route) > 0
    has_recipient = packet.recipient_id is not None
    has_signature = packet.signature is not None

    # payloadData = [originalSize preamble if compressed] + payload
    compression_preamble_size = len_field_bytes if is_compressed else 0
    payload_data_size = len(payload) + compression_preamble_size

    if version == 1 and payload_data_size > 0xFFFF:
        raise BitchatProtocolError("Payload too large for v1 packet (max 65535 bytes)")

    out = bytearray()

    # Header
    out.append(version)
    out.append(packet.type)
    out.append(packet.ttl)
    out.extend(struct.pack(">Q", packet.timestamp))  # 8 bytes BE uint64

    flags = packet.flags
    # Re-derive flags from packet fields to ensure consistency
    flags = 0
    if has_recipient:
        flags |= PacketFlag.HAS_RECIPIENT
    if has_signature:
        flags |= PacketFlag.HAS_SIGNATURE
    if is_compressed:
        flags |= PacketFlag.IS_COMPRESSED
    if has_route and version >= 2:
        flags |= PacketFlag.HAS_ROUTE
    if packet.is_rsr:
        flags |= PacketFlag.IS_RSR
    out.append(flags)

    if version == 2:
        out.extend(struct.pack(">I", payload_data_size))  # 4 bytes BE uint32
    else:
        out.extend(struct.pack(">H", payload_data_size))  # 2 bytes BE uint16

    # SenderID (always 8 bytes, zero-padded or truncated)
    sender_bytes = (packet.sender_id + b"\x00" * SENDER_ID_SIZE)[:SENDER_ID_SIZE]
    out.extend(sender_bytes)

    # RecipientID
    if has_recipient and packet.recipient_id:
        rid = (packet.recipient_id + b"\x00" * RECIPIENT_ID_SIZE)[:RECIPIENT_ID_SIZE]
        out.extend(rid)

    # Route (v2+ only)
    if has_route:
        out.append(len(route))
        for hop in route:
            hop_bytes = (hop + b"\x00" * SENDER_ID_SIZE)[:SENDER_ID_SIZE]
            out.extend(hop_bytes)

    # Compression preamble
    if is_compressed:
        if version == 2:
            out.extend(struct.pack(">I", original_payload_size))
        else:
            out.extend(struct.pack(">H", original_payload_size))

    # Payload
    out.extend(payload)

    # Signature
    if has_signature and packet.signature:
        out.extend(packet.signature[:SIGNATURE_SIZE])

    result = bytes(out)
    if padding:
        result = _apply_padding(result)
    return result


def decode(data: bytes) -> Optional[BitchatPacket]:
    """Decode binary data into a BitchatPacket.

    Returns None (never raises) on invalid or truncated input.
    Tries the raw buffer first; if that fails, tries after stripping padding.
    """
    result = _decode_core(data)
    if result is not None:
        return result
    unpadded = _strip_padding(data)
    if len(unpadded) == len(data):
        return None
    return _decode_core(unpadded)


def _decode_core(raw: bytes) -> Optional[BitchatPacket]:
    try:
        return _decode_core_raises(raw)
    except (BitchatProtocolError, struct.error, zlib.error, ValueError):
        return None


def _decode_core_raises(raw: bytes) -> BitchatPacket:
    min_size = V1_HEADER_SIZE + SENDER_ID_SIZE
    if len(raw) < min_size:
        raise PacketTooShortError(len(raw), min_size)

    offset = 0

    version = raw[offset]
    offset += 1
    if version not in (1, 2):
        raise UnsupportedVersionError(version)

    hdr_size = _header_size(version)
    if len(raw) < hdr_size + SENDER_ID_SIZE:
        raise PacketTooShortError(len(raw), hdr_size + SENDER_ID_SIZE)

    pkt_type = raw[offset]
    offset += 1
    ttl = raw[offset]
    offset += 1
    (timestamp,) = struct.unpack_from(">Q", raw, offset)
    offset += 8
    flags = raw[offset]
    offset += 1

    has_recipient = bool(flags & PacketFlag.HAS_RECIPIENT)
    has_signature = bool(flags & PacketFlag.HAS_SIGNATURE)
    is_compressed = bool(flags & PacketFlag.IS_COMPRESSED)
    has_route = version >= 2 and bool(flags & PacketFlag.HAS_ROUTE)
    is_rsr = bool(flags & PacketFlag.IS_RSR)

    len_field_bytes = _len_field_size(version)
    if version == 2:
        (payload_length,) = struct.unpack_from(">I", raw, offset)
        offset += 4
    else:
        (payload_length,) = struct.unpack_from(">H", raw, offset)
        offset += 2

    # SenderID
    if offset + SENDER_ID_SIZE > len(raw):
        raise TruncatedFieldError("senderID")
    sender_id = raw[offset : offset + SENDER_ID_SIZE]
    offset += SENDER_ID_SIZE

    # RecipientID
    recipient_id: Optional[bytes] = None
    if has_recipient:
        if offset + RECIPIENT_ID_SIZE > len(raw):
            raise TruncatedFieldError("recipientID")
        recipient_id = raw[offset : offset + RECIPIENT_ID_SIZE]
        offset += RECIPIENT_ID_SIZE

    # Route (v2+ only)
    route: Optional[list[bytes]] = None
    if has_route:
        if offset + 1 > len(raw):
            raise TruncatedFieldError("routeCount")
        route_count = raw[offset]
        offset += 1
        if route_count > 0:
            hops = []
            for i in range(route_count):
                if offset + SENDER_ID_SIZE > len(raw):
                    raise TruncatedFieldError(f"route[{i}]")
                hops.append(raw[offset : offset + SENDER_ID_SIZE])
                offset += SENDER_ID_SIZE
            route = hops

    # Payload (with optional compression preamble)
    if is_compressed:
        if payload_length < len_field_bytes:
            raise TruncatedFieldError("compressionPreamble")
        if version == 2:
            (original_size,) = struct.unpack_from(">I", raw, offset)
            offset += 4
        else:
            (original_size,) = struct.unpack_from(">H", raw, offset)
            offset += 2
        compressed_size = payload_length - len_field_bytes
        if compressed_size <= 0:
            raise TruncatedFieldError("compressedPayload")
        if offset + compressed_size > len(raw):
            raise TruncatedFieldError("compressedPayload")
        compressed_data = raw[offset : offset + compressed_size]
        offset += compressed_size

        ratio = original_size / compressed_size if compressed_size > 0 else float("inf")
        if ratio > MAX_COMPRESSION_RATIO:
            raise SuspiciousCompressionRatioError(ratio)

        try:
            payload = zlib.decompress(compressed_data, wbits=-15)  # raw inflate
        except zlib.error as e:
            raise DecompressionError(str(e)) from e
        if len(payload) != original_size:
            raise DecompressionError("decompressed size mismatch")
    else:
        if offset + payload_length > len(raw):
            raise TruncatedFieldError("payload")
        payload = raw[offset : offset + payload_length]
        offset += payload_length

    # Signature
    signature: Optional[bytes] = None
    if has_signature:
        if offset + SIGNATURE_SIZE > len(raw):
            raise TruncatedFieldError("signature")
        signature = raw[offset : offset + SIGNATURE_SIZE]
        offset += SIGNATURE_SIZE

    return BitchatPacket(
        version=version,
        type=pkt_type,
        ttl=ttl,
        timestamp=timestamp,
        flags=flags,
        sender_id=sender_id,
        recipient_id=recipient_id,
        route=route,
        payload=payload,
        signature=signature,
        is_rsr=is_rsr,
    )


def _apply_padding(data: bytes) -> bytes:
    """Apply PKCS7-style block padding."""
    block_sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    target = next((s for s in block_sizes if s >= len(data)), len(data))
    if target == len(data):
        return data
    pad_value = target - len(data)
    return data + bytes([pad_value] * pad_value)


def _strip_padding(data: bytes) -> bytes:
    """Strip PKCS7-style block padding."""
    if not data:
        return data
    pad_value = data[-1]
    if pad_value == 0 or pad_value > len(data):
        return data
    if all(b == pad_value for b in data[-pad_value:]):
        return data[:-pad_value]
    return data


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert a hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a lowercase hex string."""
    return data.hex()
