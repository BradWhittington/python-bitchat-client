import time
from dataclasses import dataclass
from enum import IntEnum

from python_bitchat_client._vendor.bitchat_protocol import (
    AnnouncementPacket as WireAnnouncementPacket,
    BitchatPacket as WirePacket,
    PacketFlag,
    PrivateMessagePacket as WirePrivateMessagePacket,
    decode as decode_wire_packet,
    decode_announcement as decode_announcement_tlv,
    decode_private_message as decode_private_message_tlv,
    encode as encode_wire_packet,
    encode_announcement as encode_announcement_tlv,
    encode_private_message as encode_private_message_tlv,
)
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey

from .keys import IdentityKeyPair
from .logging_utils import get_logger
from .models import AnnouncePacket, ChatMessage

logger = get_logger()

FLAG_HAS_RECIPIENT = int(PacketFlag.HAS_RECIPIENT)
FLAG_HAS_SIGNATURE = int(PacketFlag.HAS_SIGNATURE)

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


def _peer_hex_to_bytes(peer_id_hex: str) -> bytes:
    return bytes.fromhex(peer_id_hex)[:8].ljust(8, b"\x00")


def _peer_bytes_to_hex(peer_id: bytes | None) -> str | None:
    if peer_id is None:
        return None
    return peer_id.rstrip(b"\x00").hex()


def parse_packet(data: bytes) -> ParsedPacket:
    packet = decode_wire_packet(data)
    if packet is None:
        raise ValueError("packet parse failed")

    sender_id = _peer_bytes_to_hex(packet.sender_id)
    if sender_id is None:
        raise ValueError("packet missing sender_id")

    logger.debug("packet type=0x%02x len=%d", packet.type, len(data))

    return ParsedPacket(
        msg_type=int(packet.type),
        sender_id=sender_id,
        recipient_id=_peer_bytes_to_hex(packet.recipient_id),
        payload=packet.payload,
        ttl=packet.ttl,
        timestamp=packet.timestamp,
    )


def parse_announce_packet(packet: ParsedPacket) -> AnnouncePacket | None:
    if packet.msg_type != MessageType.ANNOUNCE.value:
        return None

    decoded = decode_announcement_tlv(packet.payload)
    if decoded is None:
        return None

    return AnnouncePacket(
        nickname=decoded.nickname,
        noise_public_key=decoded.noise_public_key,
        signing_public_key=decoded.signing_public_key,
        direct_neighbors=list(decoded.direct_neighbors or []),
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
    packet = WirePrivateMessagePacket(
        message_id=message_id[:255],
        content=text[:255],
    )
    tlv = encode_private_message_tlv(packet)
    return bytes([NOISE_PAYLOAD_PRIVATE_MESSAGE]) + tlv


def parse_private_message_payload(payload: bytes) -> tuple[str, str] | None:
    if not payload or payload[0] != NOISE_PAYLOAD_PRIVATE_MESSAGE:
        return None
    decoded = decode_private_message_tlv(payload[1:])
    if decoded is None:
        return None
    if not decoded.content:
        return None
    return decoded.message_id, decoded.content


def build_packet(
    *,
    msg_type: MessageType,
    payload: bytes,
    sender_peer_id_hex: str = "0011223344556677",
    recipient_peer_id_hex: str | None = None,
    signing_key: bytes | None = None,
) -> bytes:
    timestamp_ms = int(time.time() * 1000)
    sender_id = _peer_hex_to_bytes(sender_peer_id_hex)
    recipient_id = (
        _peer_hex_to_bytes(recipient_peer_id_hex) if recipient_peer_id_hex else None
    )

    signature: bytes | None = None
    if signing_key is not None:
        canonical_packet = WirePacket(
            version=1,
            type=int(msg_type.value),
            ttl=0,
            timestamp=timestamp_ms,
            flags=0,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            signature=None,
        )
        canonical_encoded = encode_wire_packet(canonical_packet, padding=False)
        canonical_encoded = _pad_packet(bytearray(canonical_encoded))
        signing_key_obj = SigningKey(signing_key, encoder=RawEncoder)
        signature = signing_key_obj.sign(canonical_encoded, encoder=RawEncoder)[:64]

    packet = WirePacket(
        version=1,
        type=int(msg_type.value),
        ttl=7,
        timestamp=timestamp_ms,
        flags=0,
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=payload,
        signature=signature,
    )
    encoded = encode_wire_packet(packet, padding=False)
    return _pad_packet(bytearray(encoded))


def build_announcement_packet(
    *,
    nickname: str,
    identity: IdentityKeyPair,
) -> bytes:
    payload = encode_announcement_tlv(
        WireAnnouncementPacket(
            nickname=nickname[:255],
            noise_public_key=identity.noise_public_key or b"",
            signing_public_key=identity.signing_public_key or b"",
            direct_neighbors=None,
        )
    )

    return build_packet(
        msg_type=MessageType.ANNOUNCE,
        payload=payload,
        sender_peer_id_hex=identity.short_peer_id,
        signing_key=identity.signing_private_key,
    )


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
