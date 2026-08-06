# bitchat-protocol

[![PyPI](https://img.shields.io/pypi/v/bitchat-protocol)](https://pypi.org/project/bitchat-protocol/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](https://unlicense.org)

BitChat binary protocol encode/decode for Python.

Implements the wire format from the BitChat mesh networking protocol:
binary packet encode/decode, TLV codec for announcement and private message
structures, and peer ID derivation utilities.

## Installation

```bash
pip install bitchat-protocol
```

Requires Python 3.10+.

## Quick Start

```python
from bitchat_protocol import (
    encode, decode,
    BitchatPacket, MessageType,
    encode_announcement, decode_announcement,
    AnnouncementPacket,
    peer_id_from_noise_key,
)

# Encode a broadcast message
import time
packet = BitchatPacket(
    version=1,
    type=int(MessageType.MESSAGE),
    ttl=7,
    timestamp=int(time.time() * 1000),
    flags=0,
    sender_id=bytes.fromhex('abcdef0123456789'),
    payload='Hello, BitChat!'.encode(),
)
wire = encode(packet, padding=True)   # padded for BLE transmission

# Decode from bytes received over BLE or Nostr relay
decoded = decode(wire)
if decoded:
    print('type:', decoded.type)
    print('payload:', decoded.payload.decode())
```

## API

### Packet Encode/Decode

```python
encode(packet: BitchatPacket, *, padding: bool = False) -> bytes
decode(data: bytes) -> BitchatPacket | None
```

`decode()` returns `None` (never raises) on invalid or truncated input.

### TLV: AnnouncementPacket

```python
encode_announcement(packet: AnnouncementPacket) -> bytes
decode_announcement(data: bytes) -> AnnouncementPacket | None
```

Decoder is **lenient**: unknown TLV tags are skipped (forward-compatible).

### TLV: PrivateMessagePacket

```python
encode_private_message(packet: PrivateMessagePacket) -> bytes
decode_private_message(data: bytes) -> PrivateMessagePacket | None
```

Decoder is **strict**: returns `None` on any unknown TLV tag.

### Peer ID Utilities

```python
peer_id_from_noise_key(noise_public_key: bytes) -> str   # 16-char hex
peer_id_to_bytes(peer_id: str) -> bytes                  # 8 bytes
peer_id_from_bytes(data: bytes) -> str                   # 16-char hex
nostr_geo_dm_peer_id(nostr_pubkey_hex: str) -> str       # "nostr_" + prefix
nostr_geo_chat_peer_id(nostr_pubkey_hex: str) -> str     # "nostr:" + prefix
```

### Utilities

```python
hex_to_bytes(hex_str: str) -> bytes
bytes_to_hex(data: bytes) -> str
```

## Wire Format

### v1 Header (14 bytes)
```
[version:1][type:1][ttl:1][timestamp:8 BE uint64][flags:1][payloadLen:2 BE uint16]
[senderID:8]
[recipientID:8]         — if flags & HAS_RECIPIENT
[payload:payloadLen]
[signature:64]          — if flags & HAS_SIGNATURE
```

### v2 Header (16 bytes)
Same but `payloadLen` is 4 bytes (BE uint32) and source routing is supported.

### Flags Byte
| Bit | Value | Name |
|-----|-------|------|
| 0 | 0x01 | HAS_RECIPIENT |
| 1 | 0x02 | HAS_SIGNATURE |
| 2 | 0x04 | IS_COMPRESSED |
| 3 | 0x08 | HAS_ROUTE (v2+ only) |
| 4 | 0x10 | IS_RSR |

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

## Compatibility

This package implements the same binary wire format as:
- `ios/bitchat/Protocols/BinaryProtocol.swift`
- `android/.../BinaryProtocol.kt`

Cross-language compatibility is verified by the golden fixture suite in
the [bitchat-sdk](https://github.com/bitchat-sdk) org.

## License

Unlicense — public domain.
