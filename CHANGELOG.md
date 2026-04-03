# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-03

### Added

- Flood relay/rebroadcast support in `BleBitChatClient` for transit packets with
  TTL decrement (`ttl - 1`) when relaying.
- Pluggable message dedupe cache support in both `BleBitChatClient(...)` and
  `create_client(...)` via `dedupe_cache`.
- New `src/python_bitchat_client/dedupe.py` module containing:
  - `MessageDedupCache` protocol for custom dedupe implementations.
  - `LruTtlDedupeCache` default exact in-memory LRU+TTL dedupe cache.
- Expanded GitHub automation under `.github/` including CI, CodeQL, Scorecard,
  security workflows, and Dependabot.

### Changed

- `parse_packet(...)` now stores parsed packet TTL on `ParsedPacket.ttl` to
  support relay decisions in client logic.
- `README.md` now documents relay and dedupe behavior, including custom cache
  injection and trade-offs for probabilistic caches.

### Tests

- Added coverage for default/injected dedupe cache behavior.
- Added coverage for dedupe factory pass-through in `create_client(...)`.
- Added LRU+TTL cache behavior tests (expiry and eviction).
- Added relay behavior tests (TTL decrement, duplicate suppression, and
  non-relay when TTL is 1).

## [0.1.0] - 2026-04-02

### Added

- Initial release of `python-bitchat-client`: a lightweight, headless Python
  client library for BitChat BLE mesh integrations.
- Protocol-focused foundations aligned with the BitChat whitepaper and informed
  by observed behavior in the Swift/iOS implementation for ecosystem
  compatibility.
- Core library modules for packet parsing/building, Noise protocol session
  handling, identity/key material, and client-side message models.
- A BLE-backed client implementation (`BleBitChatClient`) with a no-op fallback
  (`NullBitChatClient`) for environments where BLE backend support is missing.
- Interactive terminal harness example for manual send/receive testing.
- Initial unit test coverage across keys, protocol handling, client behavior,
  and Noise/session paths.

[0.2.0]: https://github.com/BradWhittington/python-bitchat-client/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/BradWhittington/python-bitchat-client/releases/tag/v0.1.0
