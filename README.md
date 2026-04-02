# python-bitchat-client

`python-bitchat-client` is a small, headless Python package for integrating with the
BitChat BLE mesh protocol. It comes with a basic sample client application, but it's
intended to be embedded and used by other tools.

It doesn't currently implement channel discovery.

## What this package provides

- A minimal client interface (`BitChatClient`) for:
  - starting/stopping BLE mesh connectivity
  - joining a channel (defaults to `#mesh`)
  - receiving inbound messages via callback
  - sending text messages to the current channel
  - receiving status telemetry (connected, disconnected, retries, errors)
- A BLE implementation (`BleBitChatClient`) powered by `bleak`
- A fallback no-op implementation (`NullBitChatClient`) when BLE backend is not available
- Protocol helpers for packet parsing/building

## Installation

You can install this package from pypi using `pip install python-bitchat-client`

## Basic usage

```python
from python_bitchat_client import create_client

client = create_client()
client.set_handle("crystal-jim")
client.join_channel("#mesh")

def on_message(msg):
    print(f"[{msg.channel}] <{msg.sender}> {msg.text}")

def on_status(status):
    print(f"[{status.level}] {status.code}: {status.detail}")

client.set_message_handler(on_message)
client.set_status_handler(on_status)
client.start()

ok = client.send_message("@crystal-jim say hello from python")
print("sent:", ok)
```

## Interactive test harness

A simple terminal harness is included for manual send/receive testing.

Path:

- `examples/terminal_harness.py`

Run from repository root:

```bash
uv run python examples/terminal_harness.py --handle my-handle --channel "#mesh"

# Verbose packet/transport debugging
uv run python examples/terminal_harness.py --handle my-handle --channel "#mesh" --log-level DEBUG
```

Harness commands:

- Type any line and press Enter to send it to the channel
- `/quit` or `/exit` to stop
- `/help` to print command help
- `--log-level DEBUG` to include package debug logs

Inbound channel messages are printed to stdout while the prompt remains active.

## Runtime notes and permissions

- This package does not require running your whole app as root.
- BLE access depends on host Bluetooth policy.
- On Linux, you typically need:
  - `bluetoothd` running
  - user permission to access BlueZ over D-Bus
  - distro-specific group/polkit setup

If no peer is found, the client reports status code `no_peer_found` and keeps retrying.

## Status telemetry

Common status codes emitted by the BLE client:

- `starting`
- `peer_found`
- `connected`
- `disconnected`
- `no_peer_found`
- `connect_failed`
- `send_failed`
- `stopped`
- `backend_unavailable` (fallback client)

## Development

Run package-related tests from repository root:

```bash
uv run pytest tests/test_python_bitchat_client_protocol.py tests/test_python_bitchat_client_client.py
```

Set up pre-commit hooks:

```bash
uvx pre-commit install
uvx pre-commit run --all-files
```

## Recommended branch protection

For a public open-source library, protect your default branch and require these checks:

- `CI / Test (Python 3.11)`
- `CI / Test (Python 3.12)`
- `CI / Package Build Check`
- `Dependency Security Audit / pip-audit`
- `CodeQL / Analyze (python)`

Also enable these repository security settings in GitHub:

- Dependabot alerts
- Dependabot security updates
- Code scanning alerts
