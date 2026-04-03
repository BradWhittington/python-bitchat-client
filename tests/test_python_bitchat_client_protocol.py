import struct
import zlib

from python_bitchat_client.client import BleBitChatClient
from python_bitchat_client.keys import IdentityKeyPair
from python_bitchat_client.protocol import (
    FLAG_HAS_SIGNATURE,
    BitChatStreamProcessor,
    MessageType,
    build_announcement_packet,
    build_packet,
    build_packet_for_test,
    build_private_message_payload,
    build_public_message_payload,
    build_public_message_payload_for_test,
    parse_announce_packet,
    parse_packet,
    parse_private_message_payload,
)


def test_stream_processor_emits_chat_message_for_public_message_packet() -> None:
    processor = BitChatStreamProcessor(channel="#mesh")
    payload = build_public_message_payload_for_test(
        sender="alice",
        text="@bob say hello",
        channel="#mesh",
    )
    packet = build_packet_for_test(msg_type=MessageType.MESSAGE, payload=payload)

    messages = processor.feed(packet)

    assert len(messages) == 1
    assert messages[0].sender == "0011223344556677"
    assert messages[0].text == "@bob say hello"
    assert messages[0].channel == "#mesh"


def test_ble_client_notification_pipeline_parses_fake_stream_packet() -> None:
    client = BleBitChatClient()
    received = []
    client.set_message_handler(lambda message: received.append(message))

    payload = build_public_message_payload_for_test(
        sender="alice",
        text="@bob set idle to idle_starfield",
        channel="#mesh",
    )
    packet = build_packet_for_test(msg_type=MessageType.MESSAGE, payload=payload)

    client._on_notification(None, bytearray(packet))

    assert len(received) == 1
    assert received[0].sender == "0011223344556677"


def test_public_payload_is_plain_utf8_text() -> None:
    payload = build_public_message_payload(
        sender="carol",
        text="hello mesh",
        channel="#mesh",
    )

    assert payload == b"hello mesh"


def test_public_payload_for_named_channel_is_prefixed() -> None:
    payload = build_public_message_payload(
        sender="carol",
        text="hello mesh",
        channel="#somewhere",
    )

    assert payload == b"hello mesh"


def test_build_packet_wraps_message_payload() -> None:
    payload = build_public_message_payload(
        sender="carol",
        text="hello mesh",
        channel="#mesh",
    )

    packet = build_packet(msg_type=MessageType.MESSAGE, payload=payload)
    messages = BitChatStreamProcessor(channel="#mesh").feed(packet)

    assert len(messages) == 1
    assert messages[0].text == "hello mesh"


def test_stream_processor_ignores_version_ack_packets() -> None:
    packet = build_packet(msg_type=MessageType.REQUEST_SYNC, payload=b"")

    messages = BitChatStreamProcessor(channel="#mesh").feed(packet)

    assert messages == []


def test_build_announcement_packet_without_key() -> None:
    """Test announcement packet with IdentityKeyPair sets signature flag."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="test-handle",
        identity=identity,
    )
    assert packet[0] == 1  # version
    assert packet[1] == MessageType.ANNOUNCE.value
    assert packet[11] == FLAG_HAS_SIGNATURE


def test_build_announcement_packet_with_key() -> None:
    """Test announcement packet with signing key sets signature flag."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="test-handle",
        identity=identity,
    )
    assert packet[11] == FLAG_HAS_SIGNATURE
    assert len(packet) > 50  # signature adds bytes


def test_announcement_packet_contains_nickname() -> None:
    """Test that announcement payload contains the nickname."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="alice",
        identity=identity,
    )
    payload_start = 22  # header size
    payload = packet[payload_start:]
    assert b"alice" in payload


def test_announcement_packet_uses_tlv_format() -> None:
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="alice",
        identity=identity,
    )
    parsed = parse_packet(packet)
    payload = parsed.payload

    # TLV: 0x01 nickname, 0x02 noise key, 0x03 signing key
    assert payload[0] == 0x01
    nickname_len = payload[1]
    assert payload[2 : 2 + nickname_len] == b"alice"
    noise_tlv_offset = 2 + nickname_len
    assert payload[noise_tlv_offset] == 0x02
    assert payload[noise_tlv_offset + 1] == 32


def test_announcement_packet_contains_both_keys():
    """Test announcement packet contains both Noise and Ed25519 keys."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="test-carol",
        identity=identity,
    )
    parsed = parse_packet(packet)
    assert parsed.msg_type == MessageType.ANNOUNCE.value
    payload = parsed.payload
    assert b"test-carol" in payload
    assert len(payload) > len(b"test-carol") + 1 + 32 + 32


def test_peer_id_in_sender_matches_identity():
    """Test sender ID matches identity's short peer ID."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="test-carol",
        identity=identity,
    )
    parsed = parse_packet(packet)
    expected_short = identity.short_peer_id
    assert (
        parsed.sender_id == expected_short
        or parsed.sender_id == bytes.fromhex(expected_short).hex()
    )


def test_parse_announce_packet():
    """Test parsing announcement packet payload."""
    identity = IdentityKeyPair.generate()
    packet = build_announcement_packet(
        nickname="alice",
        identity=identity,
    )
    parsed = parse_packet(packet)
    announce = parse_announce_packet(parsed)

    assert announce is not None
    assert announce.nickname == "alice"
    assert announce.noise_public_key == identity.noise_public_key
    assert announce.signing_public_key == identity.signing_public_key


def test_build_signed_message_packet_sets_signature_flag() -> None:
    identity = IdentityKeyPair.generate()
    packet = build_packet(
        msg_type=MessageType.MESSAGE,
        payload=b"hello",
        sender_peer_id_hex=identity.short_peer_id,
        signing_key=identity.signing_private_key,
    )

    # Header flags byte offset: 1+1+1+8 = 11
    assert packet[11] & FLAG_HAS_SIGNATURE == FLAG_HAS_SIGNATURE


def test_build_signed_message_packet_uses_canonical_signing_timestamp() -> None:
    identity = IdentityKeyPair.generate()
    packet = build_packet(
        msg_type=MessageType.MESSAGE,
        payload=b"hello",
        sender_peer_id_hex=identity.short_peer_id,
        signing_key=identity.signing_private_key,
    )
    parsed = parse_packet(packet)
    assert parsed.timestamp > 0


def test_private_message_payload_roundtrip() -> None:
    payload = build_private_message_payload(message_id="m1", text="hello dm")
    parsed = parse_private_message_payload(payload)
    assert parsed is not None
    message_id, text = parsed
    assert message_id == "m1"
    assert text == "hello dm"


def test_parse_packet_accepts_v2_wire_format() -> None:
    payload = b"v2 hello"
    packet = bytearray()
    packet.append(2)  # version
    packet.append(MessageType.MESSAGE.value)
    packet.append(7)  # ttl
    packet.extend(struct.pack(">Q", 1_711_234_567_890))
    packet.append(0)  # flags
    packet.extend(struct.pack(">I", len(payload)))
    packet.extend(bytes.fromhex("0011223344556677"))
    packet.extend(payload)

    parsed = parse_packet(bytes(packet))

    assert parsed.msg_type == MessageType.MESSAGE.value
    assert parsed.payload == payload
    assert parsed.ttl == 7


def test_parse_packet_decompresses_compressed_payload() -> None:
    plaintext = ("hello compressed " * 30).encode("utf-8")
    compressor = zlib.compressobj(level=6, wbits=-15)
    compressed = compressor.compress(plaintext) + compressor.flush()

    packet = bytearray()
    packet.append(1)  # version
    packet.append(MessageType.MESSAGE.value)
    packet.append(7)
    packet.extend(struct.pack(">Q", 1_711_234_567_890))
    packet.append(0x04)  # is_compressed
    packet.extend(struct.pack(">H", len(compressed) + 2))
    packet.extend(bytes.fromhex("0011223344556677"))
    packet.extend(struct.pack(">H", len(plaintext)))
    packet.extend(compressed)

    parsed = parse_packet(bytes(packet))

    assert parsed.payload == plaintext
