import asyncio
import logging

from python_bitchat_client.client import BleBitChatClient, NullBitChatClient
from python_bitchat_client.logging_utils import configure_logging, get_logger


def test_null_client_send_message_returns_false() -> None:
    client = NullBitChatClient()

    sent = client.send_message("hello world")

    assert sent is False


def test_null_client_send_direct_message_returns_false() -> None:
    client = NullBitChatClient()

    sent = client.send_direct_message("alice", "hello")

    assert sent is False


def test_null_client_lists_empty_peers_and_sessions() -> None:
    client = NullBitChatClient()

    assert client.list_peers() == []
    assert client.list_sessions() == {}


def test_null_client_reset_sessions_noop() -> None:
    client = NullBitChatClient()

    client.reset_sessions()


def test_ble_client_reset_sessions_clears_local_state() -> None:
    client = BleBitChatClient()
    client._pending_dm["peer"] = [("id1", "hello")]
    client._handshake_deadlines["peer"] = 123.0
    client._handshake_retries["peer"] = 1
    client._last_recovery_attempt["peer"] = 123.0

    client.reset_sessions()

    assert client._pending_dm == {}
    assert client._handshake_deadlines == {}
    assert client._handshake_retries == {}
    assert client._last_recovery_attempt == {}


def test_register_disconnect_callback_uses_setter_when_available() -> None:
    captured = {}

    class _ClientWithSetter:
        def set_disconnected_callback(self, callback):
            captured["callback"] = callback

    def _callback(_client) -> None:
        return

    ble_client = BleBitChatClient()

    registered = ble_client._register_disconnect_callback(
        _ClientWithSetter(),
        _callback,
    )

    assert registered is True
    assert captured["callback"] is _callback


def test_register_disconnect_callback_tolerates_missing_api() -> None:
    class _ClientWithoutSetter:
        pass

    ble_client = BleBitChatClient()
    registered = ble_client._register_disconnect_callback(
        _ClientWithoutSetter(),
        lambda _client: None,
    )

    assert registered is False


def test_configure_logging_allows_debug_output() -> None:
    configure_logging("DEBUG")

    logger = get_logger()

    assert logger.isEnabledFor(logging.DEBUG)


def test_disconnect_polling_sets_event_when_client_disconnects() -> None:
    class _FakeClient:
        is_connected = True

    async def _run() -> bool:
        client = BleBitChatClient()
        client._running = True
        disconnected = asyncio.Event()
        stop_event = asyncio.Event()
        fake = _FakeClient()

        task = asyncio.create_task(
            client._poll_disconnect_state(
                fake,
                disconnected,
                stop_event,
                poll_interval=0.01,
            )
        )
        await asyncio.sleep(0.05)
        fake.is_connected = False
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return disconnected.is_set()

    assert asyncio.run(_run()) is True


def test_disconnect_polling_stops_when_stop_event_set() -> None:
    class _FakeClient:
        is_connected = True

    async def _run() -> bool:
        client = BleBitChatClient()
        client._running = True
        disconnected = asyncio.Event()
        stop_event = asyncio.Event()
        fake = _FakeClient()

        task = asyncio.create_task(
            client._poll_disconnect_state(
                fake,
                disconnected,
                stop_event,
                poll_interval=0.01,
            )
        )
        stop_event.set()
        await asyncio.sleep(0.05)
        return task.done() and not disconnected.is_set()

    assert asyncio.run(_run()) is True
