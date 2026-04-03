import asyncio
import logging
import time

from python_bitchat_client.client import (
    BleBitChatClient,
    NullBitChatClient,
    create_client,
)
from python_bitchat_client.dedupe import LruTtlDedupeCache
from python_bitchat_client.logging_utils import configure_logging, get_logger
from python_bitchat_client.protocol import MessageType, build_packet_for_test


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


def test_default_dedupe_cache_is_instantiated() -> None:
    client = BleBitChatClient()

    assert isinstance(client._dedupe_cache, LruTtlDedupeCache)


def test_injected_dedupe_cache_is_used() -> None:
    class _FakeCache:
        def is_duplicate(self, key: str) -> bool:
            return False

        def mark_seen(self, key: str) -> None:
            _ = key

    cache = _FakeCache()
    client = BleBitChatClient(dedupe_cache=cache)

    assert client._dedupe_cache is cache


def test_create_client_passes_dedupe_cache_through() -> None:
    class _FakeCache:
        def is_duplicate(self, key: str) -> bool:
            return False

        def mark_seen(self, key: str) -> None:
            _ = key

    cache = _FakeCache()
    client = create_client(dedupe_cache=cache)

    if isinstance(client, BleBitChatClient):
        assert client._dedupe_cache is cache


def test_lru_ttl_cache_expires_entries() -> None:
    cache = LruTtlDedupeCache(max_entries=10, ttl_seconds=0.05)
    cache.mark_seen("m1")
    assert cache.is_duplicate("m1") is True

    time.sleep(0.08)

    assert cache.is_duplicate("m1") is False


def test_lru_ttl_cache_evicts_oldest_entry() -> None:
    cache = LruTtlDedupeCache(max_entries=2, ttl_seconds=5.0)
    cache.mark_seen("m1")
    cache.mark_seen("m2")
    cache.mark_seen("m3")

    assert cache.is_duplicate("m1") is False
    assert cache.is_duplicate("m2") is True
    assert cache.is_duplicate("m3") is True


def test_notification_relay_decrements_ttl_and_dedupes(monkeypatch) -> None:
    writes = []

    class _FakeClient:
        async def write_gatt_char(self, characteristic, payload, response=False):
            writes.append((characteristic, payload, response))

    class _ImmediateFuture:
        def result(self, timeout=None):
            return None

    def _run_now(coro, _loop):
        asyncio.run(coro)
        return _ImmediateFuture()

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", _run_now)

    client = BleBitChatClient()
    client._active_client = _FakeClient()
    client._loop = object()
    packet = build_packet_for_test(msg_type=MessageType.MESSAGE, payload=b"hello")

    client._on_notification(None, bytearray(packet))
    client._on_notification(None, bytearray(packet))

    assert len(writes) == 1
    relayed_payload = writes[0][1]
    assert relayed_payload[2] == packet[2] - 1


def test_notification_does_not_relay_when_ttl_is_one(monkeypatch) -> None:
    writes = []

    class _FakeClient:
        async def write_gatt_char(self, characteristic, payload, response=False):
            writes.append((characteristic, payload, response))

    class _ImmediateFuture:
        def result(self, timeout=None):
            return None

    def _run_now(coro, _loop):
        asyncio.run(coro)
        return _ImmediateFuture()

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", _run_now)

    client = BleBitChatClient()
    client._active_client = _FakeClient()
    client._loop = object()
    packet = bytearray(
        build_packet_for_test(msg_type=MessageType.MESSAGE, payload=b"hello")
    )
    packet[2] = 1

    client._on_notification(None, packet)

    assert writes == []
