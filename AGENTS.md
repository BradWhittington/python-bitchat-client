# AGENTS.md

Guidance for AI/code agents working in this repository.

## Project intent

`python-bitchat-client` is a headless Python client library for BitChat BLE mesh integrations.
It aims to be protocol-compatible with the BitChat ecosystem while staying lightweight and embeddable.

## Canonical inspiration and protocol references

Use these as primary context when implementing protocol behavior:

1. Whitepaper (protocol reference):
   - https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md
2. Swift/iOS implementation (behavioral inspiration):
   - https://github.com/permissionlesstech/bitchat/tree/main/bitchat
   - https://github.com/permissionlesstech/bitchat/tree/main/localPackages

If you find ambiguity, prefer compatibility with the whitepaper and observed Swift behavior, then document the rationale in the PR/commit message.

## Repository map

- `src/python_bitchat_client/client.py`: high-level client interface and BLE transport implementation
- `src/python_bitchat_client/protocol.py`: packet/message parsing and packet builders
- `src/python_bitchat_client/noise_session.py`, `src/python_bitchat_client/noise_protocol.py`: Noise session and crypto framing logic
- `src/python_bitchat_client/keys.py`: identity/key derivation and peer ID material
- `src/python_bitchat_client/models.py`: core data models
- `examples/terminal_harness.py`: manual interactive harness
- `tests/`: unit tests

## Local workflow

- Python: `>=3.11`
- Package/deps: `uv`
- Build package: `uv build`
- Run tests: `uv run pytest`
- Run example harness: `uv run python examples/terminal_harness.py --handle my-handle --channel "#mesh"`

## Engineering expectations for agents

1. Keep changes scoped and minimal; do not refactor unrelated areas.
2. Preserve public API stability unless explicitly asked to introduce breaking changes.
3. Add or update tests for behavior changes (especially protocol parsing/building and session behavior).
4. Prefer deterministic tests with no BLE hardware dependency in unit tests.
5. When adding protocol constants/fields, keep naming and wire-format semantics aligned with whitepaper/Swift references.
6. Update `README.md` when user-facing behavior, APIs, or setup steps change.

## Packaging and release notes

- Build backend is `hatchling` via `pyproject.toml`.
- For any release/version bump, update `CHANGELOG.md` in the same branch/PR.
- Changelog conventions:
  - Follow Keep a Changelog format and SemVer version headings.
  - Add a dated version section (for example `## [0.2.0] - 2026-04-03`).
  - Group entries under standard sections as applicable: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
  - Keep entries user-facing and behavior-focused (avoid low-level commit noise).
  - Maintain/update version comparison links at the bottom of `CHANGELOG.md`.
- Before publish, run:
  1. `uv build`
  2. `uv run python -m twine check dist/*`
  3. `uv publish --dry-run`
- Publish with: `uv publish --token <pypi-token>`

## Safety guardrails

- Never commit secrets or tokens.
- Avoid destructive git operations unless explicitly requested.
- Do not silently change protocol behavior; if needed, include tests and a short compatibility note.
