from dataclasses import dataclass


@dataclass(frozen=True)
class ChatMessage:
    sender: str
    text: str
    channel: str = "#mesh"
    is_private: bool = False


@dataclass
class AnnouncePacket:
    nickname: str
    noise_public_key: bytes
    signing_public_key: bytes
    direct_neighbors: list[bytes]
    sender_peer_id: str
    timestamp: int


@dataclass(frozen=True)
class PeerInfo:
    peer_id: str
    nickname: str
