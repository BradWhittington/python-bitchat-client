# v0.2.0 Release Notes

## Overview

This release adds BLE mesh relay/rebroadcast support with a pluggable dedupe cache,
plus protocol and test updates needed to validate relay behavior. It also includes
repository automation updates for CI/security workflows.

## Code changes since `v0.1.0`

### Feature: relay rebroadcast with dedupe

- Added packet relay path in `BleBitChatClient` so inbound transit packets can be
  rebroadcast when `ttl > 1`, with outbound relay packets using `ttl - 1`.
- Added dedupe cache support to the client constructor and `create_client(...)`
  factory via a new `dedupe_cache` parameter.
- Added new module `src/python_bitchat_client/dedupe.py` with:
  - `MessageDedupCache` protocol for custom cache implementations.
  - `LruTtlDedupeCache` default in-memory exact-match cache with bounded size and
    TTL expiration.

### Protocol update

- `parse_packet(...)` now records packet TTL on `ParsedPacket.ttl`, enabling
  relay decisions based on parsed packet metadata.

### Tests

- Expanded `tests/test_python_bitchat_client_client.py` to cover:
  - Default dedupe cache creation.
  - Injected custom dedupe cache wiring.
  - Factory pass-through of dedupe cache.
  - LRU+TTL dedupe behavior (expiry and eviction).
  - Relay behavior (TTL decrement, duplicate suppression, no relay at TTL=1).

### Documentation updates

- Updated `README.md` feature list and added a new "Relay and dedupe behavior"
  section with usage example for custom dedupe caches.

### Repository automation updates

- Added/updated GitHub automation files under `.github/` for CI, CodeQL,
  Scorecards, security checks, Dependabot, and action pin/version updates.

## Commit history from `v0.1.0` to `HEAD`

- `1c6be4e` Add Python package testing workflow for versions 3.12, 3.13, and 3.14 to workflow
- `48fe861` Add free security automation and action hardening
- `69776f3` Remove legacy Python package workflow
- `6fdb442` Expand CI matrix to Python 3.13
- `7a64ecc` Bump the github-actions group with 5 updates (#1)
- `316fea7` Remove random (#2)
- `dfd1f0b` Add relay rebroadcast with pluggable dedupe cache (#3)
- `b337b3b` Try get ossf scorecard working (#4)
- `f1b72b3` Update Scorecard workflow actions for Node 24 (#5)
- `fff77e5` Update workflow action pins to latest versions (#6)
