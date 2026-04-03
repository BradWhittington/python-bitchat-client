import struct
import time
from dataclasses import dataclass
from enum import IntEnum

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from .keys import IdentityKeyPair
from .logging_utils import get_logger
from .models import AnnouncePacket, ChatMessage

logger = get_logger()

FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02

BROADCAST_RECIPIENT = b"\xff" * 8

NOISE_PAYLOAD_PRIVATE_MESSAGE = 0x01
NOISE_PAYLOAD_READ_RECEIPT = 0x02
NOISE_PAYLOAD_DELIVERED = 0x03


class MessageType(IntEnum):
    ANNOUNCE = 0x01
    MESSAGE = 0x02
    LEAVE = 0x03
    NOISE_HANDSHAKE = 0x10
    NOISE_ENCRYPTED = 0x11
    FRAGMENT = 0x20
    REQUEST_SYNC = 0x21
    FILE_TRANSFER = 0x22


@dataclass(frozen=True)
class ParsedPacket:
    msg_type: int
    sender_id: str
    recipient_id: str | None
    payload: bytes
    ttl: int = 0
    timestamp: int = 0


def parse_packet(data: bytes) -> ParsedPacket:
    if len(data) < 21:
        raise ValueError("packet too small")

    offset = 0
    version = data[offset]
    offset += 1
    if version != 1:
        raise ValueError("unsupported packet version")

    msg_type = int(data[offset])
    offset += 1
    logger.debug("packet type=0x%02x len=%d", msg_type, len(data))

    ttl = data[offset]
    offset += 1

    timestamp = struct.unpack(">Q", data[offset : offset + 8])[0]
    offset += 8

    flags = data[offset]
    offset += 1

    payload_len = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2

    sender_raw = data[offset : offset + 8]
    sender_id = sender_raw.rstrip(b"\x00").hex()
    offset += 8

    recipient_id = None
    if flags & FLAG_HAS_RECIPIENT:
        recipient_raw = data[offset : offset + 8]
        recipient_id = recipient_raw.rstrip(b"\x00").hex()
        offset += 8

    payload = data[offset : offset + payload_len]
    return ParsedPacket(
        msg_type=msg_type,
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=payload,
        ttl=ttl,
        timestamp=timestamp,
    )


def parse_announce_packet(packet: ParsedPacket) -> AnnouncePacket | None:
    """Parse TLV announcement packet payload."""
    if packet.msg_type != MessageType.ANNOUNCE.value:
        return None

    payload = packet.payload

    nickname: str | None = None
    noise_public_key: bytes | None = None
    signing_public_key: bytes | None = None
    direct_neighbors: list[bytes] = []

    offset = 0
    while offset + 2 <= len(payload):
        tlv_type = payload[offset]
        tlv_len = payload[offset + 1]
        offset += 2
        if offset + tlv_len > len(payload):
            return None
        value = payload[offset : offset + tlv_len]
        offset += tlv_len

        if tlv_type == 0x01:
            nickname = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x02:
            noise_public_key = value
        elif tlv_type == 0x03:
            signing_public_key = value
        elif tlv_type == 0x04:
            if tlv_len % 8 != 0:
                return None
            for i in range(0, tlv_len, 8):
                direct_neighbors.append(value[i : i + 8])

    if nickname is None or noise_public_key is None or signing_public_key is None:
        return None

    return AnnouncePacket(
        nickname=nickname,
        noise_public_key=noise_public_key,
        signing_public_key=signing_public_key,
        direct_neighbors=direct_neighbors,
        sender_peer_id=packet.sender_id,
        timestamp=getattr(packet, "timestamp", 0),
    )


class BitChatStreamProcessor:
    def __init__(self, *, channel: str = "#mesh") -> None:
        self._channel = channel

    def feed(self, data: bytes) -> list[ChatMessage]:
        packet = parse_packet(data)
        if packet.msg_type != MessageType.MESSAGE.value:
            return []

        content = packet.payload.decode("utf-8", errors="ignore").strip()
        if not content:
            return []

        return [
            ChatMessage(
                sender=packet.sender_id,
                text=content,
                channel=self._channel,
            )
        ]


def build_public_message_payload(
    *,
    sender: str,
    text: str,
    channel: str = "#mesh",
    sender_peer_id: str | None = None,
) -> bytes:
    _ = (sender, channel, sender_peer_id)
    return text.encode("utf-8")


def build_private_message_payload(*, message_id: str, text: str) -> bytes:
    msg_id_bytes = message_id.encode("utf-8")[:255]
    content_bytes = text.encode("utf-8")[:255]
    tlv = bytearray()
    tlv.append(0x00)
    tlv.append(len(msg_id_bytes))
    tlv.extend(msg_id_bytes)
    tlv.append(0x01)
    tlv.append(len(content_bytes))
    tlv.extend(content_bytes)
    return bytes([NOISE_PAYLOAD_PRIVATE_MESSAGE]) + bytes(tlv)


def parse_private_message_payload(payload: bytes) -> tuple[str, str] | None:
    if not payload or payload[0] != NOISE_PAYLOAD_PRIVATE_MESSAGE:
        return None
    data = payload[1:]
    offset = 0
    message_id = ""
    content = ""
    while offset + 2 <= len(data):
        tlv_type = data[offset]
        tlv_len = data[offset + 1]
        offset += 2
        if offset + tlv_len > len(data):
            return None
        value = data[offset : offset + tlv_len]
        offset += tlv_len
        if tlv_type == 0x00:
            message_id = value.decode("utf-8", errors="replace")
        elif tlv_type == 0x01:
            content = value.decode("utf-8", errors="replace")
    if not content:
        return None
    return message_id, content


def build_packet(
    *,
    msg_type: MessageType,
    payload: bytes,
    sender_peer_id_hex: str = "0011223344556677",
    recipient_peer_id_hex: str | None = None,
    signing_key: bytes | None = None,
) -> bytes:
    timestamp_ms = int(time.time() * 1000)
    flags = 0
    if recipient_peer_id_hex:
        flags |= FLAG_HAS_RECIPIENT

    signature: bytes | None = None
    if signing_key is not None:
        canonical_packet = _build_base_packet(
            msg_type=msg_type,
            payload=payload,
            sender_peer_id_hex=sender_peer_id_hex,
            recipient_peer_id_hex=recipient_peer_id_hex,
            flags=flags,
            ttl=0,
            timestamp_ms=timestamp_ms,
        )
        canonical_packet = _pad_packet(canonical_packet)
        signing_key_obj = SigningKey(signing_key, encoder=RawEncoder)
        signature = signing_key_obj.sign(canonical_packet, encoder=RawEncoder)[:64]
        flags |= FLAG_HAS_SIGNATURE

    packet = _build_base_packet(
        msg_type=msg_type,
        payload=payload,
        sender_peer_id_hex=sender_peer_id_hex,
        recipient_peer_id_hex=recipient_peer_id_hex,
        flags=flags,
        ttl=7,
        timestamp_ms=timestamp_ms,
    )
    if signature is not None:
        packet.extend(signature)
    return _pad_packet(packet)


def build_announcement_packet(
    *,
    nickname: str,
    identity: IdentityKeyPair,
) -> bytes:
    """Build TLV AnnouncementPacket compatible with iOS implementation."""
    payload = bytearray()

    nickname_bytes = nickname.encode("utf-8")[:255]
    payload.append(0x01)
    payload.append(len(nickname_bytes))
    payload.extend(nickname_bytes)

    noise_public_key = identity.noise_public_key or b""
    signing_public_key = identity.signing_public_key or b""

    payload.append(0x02)
    payload.append(len(noise_public_key))
    payload.extend(noise_public_key)

    payload.append(0x03)
    payload.append(len(signing_public_key))
    payload.extend(signing_public_key)

    payload_bytes = bytes(payload)

    return build_packet(
        msg_type=MessageType.ANNOUNCE,
        payload=payload_bytes,
        sender_peer_id_hex=identity.short_peer_id,
        signing_key=identity.signing_private_key,
    )


def _build_base_packet(
    *,
    msg_type: MessageType,
    payload: bytes,
    sender_peer_id_hex: str,
    recipient_peer_id_hex: str | None,
    flags: int,
    ttl: int,
    timestamp_ms: int,
) -> bytearray:
    packet = bytearray()
    packet.append(1)
    packet.append(msg_type.value)
    packet.append(ttl)
    packet.extend(struct.pack(">Q", timestamp_ms))
    packet.append(flags)
    packet.extend(struct.pack(">H", len(payload)))
    sender_bytes = bytes.fromhex(sender_peer_id_hex)
    packet.extend(sender_bytes[:8].ljust(8, b"\x00"))
    if recipient_peer_id_hex:
        recipient_bytes = bytes.fromhex(recipient_peer_id_hex)
        packet.extend(recipient_bytes[:8].ljust(8, b"\x00"))
    packet.extend(payload)
    return packet


def _pad_packet(packet: bytearray) -> bytes:
    block_sizes = [256, 512, 1024, 2048]
    total_size = len(packet) + 16
    target_size = next((b for b in block_sizes if total_size <= b), len(packet))
    padding_needed = target_size - len(packet)
    if 0 < padding_needed <= 255:
        packet.extend([padding_needed] * padding_needed)
    return bytes(packet)


def build_public_message_payload_for_test(
    *,
    sender: str,
    text: str,
    channel: str = "#mesh",
) -> bytes:
    return build_public_message_payload(sender=sender, text=text, channel=channel)


def build_packet_for_test(*, msg_type: MessageType, payload: bytes) -> bytes:
    return build_packet(msg_type=msg_type, payload=payload)
