"""Error taxonomy for bitchat_protocol."""


class BitchatProtocolError(Exception):
    """Base exception for all BitChat protocol errors."""


class PacketTooShortError(BitchatProtocolError):
    """Input buffer is too short to contain a valid packet."""
    def __init__(self, received: int, minimum: int) -> None:
        super().__init__(f"Packet too short: {received} bytes (minimum {minimum})")


class UnsupportedVersionError(BitchatProtocolError):
    """Version field is not 1 or 2."""
    def __init__(self, version: int) -> None:
        super().__init__(f"Unsupported protocol version: {version}")


class TruncatedFieldError(BitchatProtocolError):
    """A required field is truncated or missing."""
    def __init__(self, field: str) -> None:
        super().__init__(f"Truncated field: {field}")


class DecompressionError(BitchatProtocolError):
    """Payload decompression failed."""


class SuspiciousCompressionRatioError(BitchatProtocolError):
    """Compression ratio exceeded the security limit (50,000:1)."""
    def __init__(self, ratio: float) -> None:
        super().__init__(f"Suspicious compression ratio: {ratio:.0f}:1 (limit 50000:1)")


class TLVDecodeError(BitchatProtocolError):
    """TLV payload could not be decoded."""


class TLVEncodeError(BitchatProtocolError):
    """TLV payload could not be encoded (field too long etc.)."""
