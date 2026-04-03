"""Tests for the binary codec — encode/decode round-trips and error cases."""

from python_bitchat_client._vendor.bitchat_protocol import (
    BitchatPacket,
    MessageType,
    PacketFlag,
    bytes_to_hex,
    decode,
    encode,
    hex_to_bytes,
)

SENDER = bytes.fromhex("abcdef0123456789")
RECIPIENT = bytes.fromhex("0102030405060708")


def make_packet(**kwargs) -> BitchatPacket:
    defaults = dict(
        version=1,
        type=int(MessageType.MESSAGE),
        ttl=7,
        timestamp=0,
        flags=0,
        sender_id=SENDER,
        payload=b"",
    )
    defaults.update(kwargs)
    return BitchatPacket(**defaults)


class TestEncodeDecodeRoundTrip:
    def test_broadcast_plain_text(self):
        payload = b"Hello, BitChat!"
        pkt = make_packet(payload=payload)
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.version == 1
        assert decoded.type == int(MessageType.MESSAGE)
        assert decoded.ttl == 7
        assert decoded.timestamp == 0
        assert decoded.sender_id == SENDER
        assert decoded.payload == payload
        assert decoded.recipient_id is None
        assert decoded.signature is None

    def test_empty_payload(self):
        pkt = make_packet(payload=b"")
        wire = encode(pkt, padding=False)
        assert len(wire) == 22  # 14 header + 8 senderID
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.payload == b""

    def test_directed_message_with_recipient(self):
        payload = bytes.fromhex("01deadbeef")
        pkt = make_packet(
            type=int(MessageType.NOISE_ENCRYPTED),
            flags=int(PacketFlag.HAS_RECIPIENT),
            recipient_id=RECIPIENT,
            payload=payload,
        )
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.recipient_id == RECIPIENT
        assert decoded.payload == payload

    def test_message_with_signature(self):
        signature = bytes([0xAB] * 64)
        pkt = make_packet(
            flags=int(PacketFlag.HAS_SIGNATURE),
            payload=b"signed",
            signature=signature,
        )
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.signature is not None
        assert len(decoded.signature) == 64
        assert decoded.signature[0] == 0xAB

    def test_v2_packet(self):
        payload = b"v2 test"
        pkt = make_packet(version=2, payload=payload)
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.version == 2
        assert decoded.payload == payload

    def test_v2_with_route(self):
        hop1 = bytes.fromhex("aabbccddeeff0011")
        hop2 = bytes.fromhex("2233445566778899")
        pkt = make_packet(
            version=2,
            type=int(MessageType.NOISE_ENCRYPTED),
            flags=int(PacketFlag.HAS_RECIPIENT) | int(PacketFlag.HAS_ROUTE),
            recipient_id=RECIPIENT,
            route=[hop1, hop2],
            payload=bytes.fromhex("deadbeef"),
        )
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.route is not None
        assert len(decoded.route) == 2
        assert decoded.route[0] == hop1
        assert decoded.route[1] == hop2

    def test_padding_roundtrip(self):
        pkt = make_packet(payload=b"padded")
        with_padding = encode(pkt, padding=True)
        without_padding = encode(pkt, padding=False)
        assert len(with_padding) > len(without_padding)
        decoded = decode(with_padding)
        assert decoded is not None
        assert decoded.payload == b"padded"

    def test_unicode_payload(self):
        payload = "こんにちは".encode("utf-8")
        pkt = make_packet(payload=payload)
        wire = encode(pkt, padding=False)
        decoded = decode(wire)
        assert decoded is not None
        assert decoded.payload == payload


class TestDecodeFailures:
    def test_empty_buffer(self):
        assert decode(b"") is None

    def test_too_short(self):
        assert decode(b"\x01" * 10) is None

    def test_unknown_version(self):
        bad = bytes([3]) + bytes(29)
        assert decode(bad) is None

    def test_version_zero(self):
        bad = bytes([0]) + bytes(29)
        assert decode(bad) is None

    def test_truncated_payload(self):
        pkt = make_packet(payload=b"Hello")
        wire = encode(pkt, padding=False)
        assert decode(wire[:-3]) is None

    def test_truncated_signature(self):
        pkt = make_packet(
            flags=int(PacketFlag.HAS_SIGNATURE),
            payload=b"x",
            signature=bytes(64),
        )
        wire = encode(pkt, padding=False)
        assert decode(wire[:-10]) is None


class TestHexUtils:
    def test_hex_roundtrip(self):
        hex_str = "deadbeef0102030405060708"
        assert bytes_to_hex(hex_to_bytes(hex_str)) == hex_str

    def test_bytes_to_hex_lowercase(self):
        assert bytes_to_hex(b"\xab\xcd\xef") == "abcdef"

    def test_hex_to_bytes_correct(self):
        assert hex_to_bytes("0102ff") == bytes([0x01, 0x02, 0xFF])
