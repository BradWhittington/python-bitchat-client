import asyncio
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .dedupe import LruTtlDedupeCache, MessageDedupCache
from .keys import IdentityKeyPair
from .logging_utils import get_logger
from .models import ChatMessage, PeerInfo
from .noise_session import NoiseSessionManager
from .protocol import (
    BitChatStreamProcessor,
    MessageType,
    build_announcement_packet,
    build_packet,
    build_private_message_payload,
    build_public_message_payload,
    parse_announce_packet,
    parse_packet,
    parse_private_message_payload,
)

logger = get_logger()


@dataclass(frozen=True)
class ClientStatus:
    level: str
    code: str
    detail: str


class BitChatClient(Protocol):
    def set_message_handler(self, handler: Callable[[ChatMessage], None]) -> None: ...

    def set_handle(self, handle: str) -> None: ...

    def join_channel(self, channel: str) -> None: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def set_status_handler(self, handler: Callable[[ClientStatus], None]) -> None: ...

    def send_message(self, text: str) -> bool: ...

    def send_direct_message(self, target: str, text: str) -> bool: ...

    def list_peers(self) -> list[PeerInfo]: ...

    def list_sessions(self) -> dict[str, str]: ...

    def reset_sessions(self) -> None: ...


class NullBitChatClient:
    def __init__(self) -> None:
        self._handler: Callable[[ChatMessage], None] | None = None
        self._status_handler: Callable[[ClientStatus], None] | None = None
        self._handle = ""
        self._channel = "#mesh"

    def set_message_handler(self, handler: Callable[[ChatMessage], None]) -> None:
        self._handler = handler

    def set_handle(self, handle: str) -> None:
        self._handle = handle

    def join_channel(self, channel: str) -> None:
        self._channel = channel

    def start(self) -> None:
        self._emit_status("warning", "backend_unavailable", "BLE backend unavailable")

    def stop(self) -> None:
        return

    def send_message(self, text: str) -> bool:
        _ = text
        self._emit_status("warning", "send_unavailable", "BLE backend unavailable")
        return False

    def send_direct_message(self, target: str, text: str) -> bool:
        _ = (target, text)
        self._emit_status("warning", "send_unavailable", "BLE backend unavailable")
        return False

    def list_peers(self) -> list[PeerInfo]:
        return []

    def list_sessions(self) -> dict[str, str]:
        return {}

    def reset_sessions(self) -> None:
        return

    def set_status_handler(self, handler: Callable[[ClientStatus], None]) -> None:
        self._status_handler = handler

    def _emit_status(self, level: str, code: str, detail: str) -> None:
        if self._status_handler is None:
            return
        self._status_handler(ClientStatus(level=level, code=code, detail=detail))


class BleBitChatClient:
    SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
    CHARACTERISTIC_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
    HANDSHAKE_TIMEOUT_SECONDS = 4.0
    HANDSHAKE_MAX_RETRIES = 1
    RECOVERY_COOLDOWN_SECONDS = 3.0

    def __init__(
        self,
        identity: IdentityKeyPair | None = None,
        dedupe_cache: MessageDedupCache | None = None,
    ) -> None:
        self._handler: Callable[[ChatMessage], None] | None = None
        self._status_handler: Callable[[ClientStatus], None] | None = None
        self._handle = ""
        self._channel = "#mesh"
        self._running = False
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        self._processor = BitChatStreamProcessor(channel="#mesh")
        self._identity = identity if identity else IdentityKeyPair.generate()
        self._peer_id_hex = self._identity.short_peer_id
        self._active_client: Any | None = None
        self._peer_map: dict[str, str] = {}
        self._noise = NoiseSessionManager(
            local_static_private_key=self._identity.noise_private_key,
        )
        self._pending_dm: dict[str, list[tuple[str, str]]] = {}
        self._handshake_deadlines: dict[str, float] = {}
        self._handshake_retries: dict[str, int] = {}
        self._last_recovery_attempt: dict[str, float] = {}
        self._watchdog_task: asyncio.Task[None] | None = None
        self._dedupe_cache = dedupe_cache or LruTtlDedupeCache()

    def set_message_handler(self, handler: Callable[[ChatMessage], None]) -> None:
        self._handler = handler

    def set_status_handler(self, handler: Callable[[ClientStatus], None]) -> None:
        self._status_handler = handler

    def set_handle(self, handle: str) -> None:
        self._handle = handle

    def join_channel(self, channel: str) -> None:
        self._channel = channel
        self._processor = BitChatStreamProcessor(channel=channel)

    def start(self) -> None:
        if self._running:
            return
        self.reset_sessions()
        self._running = True
        logger.debug("starting BLE client thread")
        self._thread = threading.Thread(target=self._run_thread, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def send_message(self, text: str) -> bool:
        cleaned = text.strip()
        if not cleaned:
            return False
        if self._loop is None:
            self._emit_status("warning", "not_connected", "cannot send before connect")
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._send_public_message(cleaned),
            self._loop,
        )
        try:
            sent = bool(future.result(timeout=5.0))
            logger.debug("send_message result=%s chars=%d", sent, len(cleaned))
            return sent
        except Exception as exc:
            self._emit_status("error", "send_failed", str(exc))
            return False

    def send_direct_message(self, target: str, text: str) -> bool:
        cleaned = text.strip()
        if not cleaned:
            return False
        peer_id = self._resolve_peer_target(target)
        if peer_id is None:
            self._emit_status(
                "warning", "unknown_peer", f"unknown peer target: {target}"
            )
            return False
        if self._loop is None:
            self._emit_status("warning", "not_connected", "cannot send before connect")
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._send_direct_message(peer_id=peer_id, text=cleaned),
            self._loop,
        )
        try:
            return bool(future.result(timeout=8.0))
        except Exception as exc:
            self._emit_status("error", "send_dm_failed", str(exc))
            return False

    def list_peers(self) -> list[PeerInfo]:
        peers: list[PeerInfo] = []
        for peer_id, nickname in sorted(
            self._peer_map.items(), key=lambda item: item[1]
        ):
            peers.append(PeerInfo(peer_id=peer_id, nickname=nickname))
        return peers

    def list_sessions(self) -> dict[str, str]:
        return self._noise.session_states()

    def reset_sessions(self) -> None:
        self._reset_all_sessions(reason="manual_reset", emit_status=True)

    def _run_thread(self) -> None:
        try:
            asyncio.run(self._run_loop())
        except Exception as exc:
            self._emit_status("error", "runtime_failed", str(exc))

    async def _run_loop(self) -> None:
        from bleak import BleakClient, BleakScanner

        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self._emit_status("info", "starting", "starting BLE BitChat client")

        while (
            self._running
            and self._stop_event is not None
            and not self._stop_event.is_set()
        ):
            device = await BleakScanner.find_device_by_filter(
                lambda d, ad: (
                    self.SERVICE_UUID.lower()
                    in {uuid.lower() for uuid in (ad.service_uuids or [])}
                ),
                timeout=5.0,
            )
            if device is None:
                self._emit_status(
                    "warning",
                    "no_peer_found",
                    "no BitChat BLE peer found; retrying",
                )
                await asyncio.sleep(2.0)
                continue

            logger.debug(
                "found peer address=%s", getattr(device, "address", "<unknown>")
            )

            self._emit_status(
                "info",
                "peer_found",
                f"connecting to {device.address}",
            )

            try:
                async with BleakClient(device) as client:
                    self._active_client = client
                    self._reset_all_sessions(reason="connect_reset", emit_status=True)
                    disconnected = asyncio.Event()

                    def _on_disconnect(
                        _client: Any,
                        disconnected_event: asyncio.Event = disconnected,
                    ) -> None:
                        disconnected_event.set()

                    disconnected_callback_set = self._register_disconnect_callback(
                        client,
                        _on_disconnect,
                    )
                    if not disconnected_callback_set:
                        self._emit_status(
                            "warning",
                            "disconnect_callback_unavailable",
                            "Bleak disconnect callback API unavailable; relying on notify/write failures for reconnect",
                        )
                    await client.start_notify(
                        self.CHARACTERISTIC_UUID,
                        self._on_notification,
                    )
                    self._emit_status("info", "connected", "connected to BitChat peer")

                    if self._handle:
                        await self._send_announce(client)

                    self._watchdog_task = asyncio.create_task(
                        self._handshake_watchdog(client)
                    )

                    if self._stop_event is None:
                        return
                    disconnect_poll_task = asyncio.create_task(
                        self._poll_disconnect_state(
                            client,
                            disconnected,
                            self._stop_event,
                        )
                    )
                    done, _pending = await asyncio.wait(
                        [
                            asyncio.create_task(self._stop_event.wait()),
                            asyncio.create_task(disconnected.wait()),
                            disconnect_poll_task,
                        ],
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in done:
                        _ = task.result()
                    for task in _pending:
                        task.cancel()

                    await client.stop_notify(self.CHARACTERISTIC_UUID)

                    if self._watchdog_task is not None:
                        self._watchdog_task.cancel()
                        try:
                            await self._watchdog_task
                        except asyncio.CancelledError:
                            pass
                        self._watchdog_task = None

                    if disconnected.is_set() and self._running:
                        self._emit_status(
                            "warning",
                            "disconnected",
                            "peer disconnected; reconnecting",
                        )
                self._active_client = None
            except Exception as exc:
                self._active_client = None
                self._emit_status("error", "connect_failed", str(exc))
                await asyncio.sleep(2.0)

        self._emit_status("info", "stopped", "BLE BitChat client stopped")

    async def _send_announce(self, client: Any) -> None:
        logger.debug("_send_announce called with handle=%s", self._handle)
        try:
            packet = build_announcement_packet(
                nickname=self._handle,
                identity=self._identity,
            )
            logger.debug("_send_announce packet size=%d", len(packet))
            await client.write_gatt_char(
                self.CHARACTERISTIC_UUID, packet, response=False
            )
            logger.debug("_send_announce completed successfully")
        except Exception as exc:
            logger.error("_send_announce failed: %s", exc)
            raise

    async def _send_public_message(self, text: str) -> bool:
        client = self._active_client
        if client is None:
            self._emit_status("warning", "not_connected", "cannot send before connect")
            return False

        sender = self._handle or "python-client"
        payload = build_public_message_payload(
            sender=sender,
            text=text,
            channel=self._channel,
            sender_peer_id=self._peer_id_hex,
        )
        packet = build_packet(
            msg_type=MessageType.MESSAGE,
            payload=payload,
            sender_peer_id_hex=self._peer_id_hex,
            signing_key=self._identity.signing_private_key,
        )
        await client.write_gatt_char(self.CHARACTERISTIC_UUID, packet, response=False)
        return True

    async def _send_direct_message(self, *, peer_id: str, text: str) -> bool:
        client = self._active_client
        if client is None:
            self._emit_status("warning", "not_connected", "cannot send before connect")
            return False

        if not self._noise.has_established_session(peer_id):
            self._pending_dm.setdefault(peer_id, []).append((str(uuid.uuid4()), text))
            if not self._noise.has_session(peer_id):
                await self._send_handshake_init(client=client, peer_id=peer_id)
            self._emit_status(
                "info", "dm_queued", f"queued DM for {peer_id} until handshake"
            )
            return True

        payload = build_private_message_payload(message_id=str(uuid.uuid4()), text=text)
        encrypted = self._noise.encrypt(peer_id=peer_id, plaintext=payload)
        packet = build_packet(
            msg_type=MessageType.NOISE_ENCRYPTED,
            payload=encrypted,
            sender_peer_id_hex=self._peer_id_hex,
            recipient_peer_id_hex=peer_id,
        )
        await client.write_gatt_char(self.CHARACTERISTIC_UUID, packet, response=False)
        return True

    def _on_notification(self, _characteristic: Any, data: bytearray) -> None:
        logger.debug("notification bytes=%d", len(data))
        try:
            packet = parse_packet(bytes(data))
            self._maybe_relay_packet(packet, bytes(data))

            if packet.msg_type == MessageType.ANNOUNCE.value:
                announce = parse_announce_packet(packet)
                if announce:
                    self._peer_map[announce.sender_peer_id] = announce.nickname
                    logger.debug(
                        "received announce from %s: %s",
                        announce.sender_peer_id,
                        announce.nickname,
                    )
                return

            if packet.msg_type == MessageType.NOISE_HANDSHAKE.value:
                self._handle_noise_handshake(packet)
                return

            if packet.msg_type == MessageType.NOISE_ENCRYPTED.value:
                self._handle_noise_encrypted(packet)
                return

            messages = self._processor.feed(bytes(data))
        except Exception as exc:
            self._emit_status("warning", "packet_parse_failed", str(exc))
            return
        logger.debug("parsed chat messages=%d", len(messages))
        if self._handler is None:
            return
        for message in messages:
            self._handler(message)

    def _maybe_relay_packet(self, packet: Any, raw_packet: bytes) -> None:
        if packet.sender_id == self._peer_id_hex:
            return

        dedupe_key = f"{packet.sender_id}-{packet.timestamp}-{packet.msg_type}"
        if self._dedupe_cache.is_duplicate(dedupe_key):
            return
        self._dedupe_cache.mark_seen(dedupe_key)

        if packet.ttl <= 1:
            return

        active_client = self._active_client
        if self._loop is None or active_client is None:
            return

        relay_packet = bytearray(raw_packet)
        relay_packet[2] = packet.ttl - 1

        async def _relay() -> None:
            try:
                await active_client.write_gatt_char(
                    self.CHARACTERISTIC_UUID,
                    bytes(relay_packet),
                    response=False,
                )
            except Exception as exc:
                self._emit_status("warning", "relay_failed", str(exc))

        asyncio.run_coroutine_threadsafe(_relay(), self._loop)

    def _handle_noise_handshake(self, packet) -> None:
        if packet.recipient_id and packet.recipient_id != self._peer_id_hex:
            return
        try:
            response = self._noise.handle_incoming_handshake(
                peer_id=packet.sender_id,
                message=packet.payload,
            )
            active_client = self._active_client
            if (
                response is not None
                and self._loop is not None
                and active_client is not None
            ):
                response_bytes = response
                client_ref = active_client

                async def _send_handshake_response() -> None:
                    out = build_packet(
                        msg_type=MessageType.NOISE_HANDSHAKE,
                        payload=response_bytes,
                        sender_peer_id_hex=self._peer_id_hex,
                        recipient_peer_id_hex=packet.sender_id,
                    )
                    await client_ref.write_gatt_char(
                        self.CHARACTERISTIC_UUID,
                        out,
                        response=False,
                    )

                asyncio.run_coroutine_threadsafe(
                    _send_handshake_response(),
                    self._loop,
                )

            if self._noise.has_established_session(packet.sender_id):
                recovered = bool(self._pending_dm.get(packet.sender_id))
                self._mark_handshake_established(
                    packet.sender_id,
                    recovered=recovered,
                )
                self._flush_pending_dm(packet.sender_id)
        except Exception as exc:
            # Retry once from a fresh session state to recover from crossed
            # initiations/retransmits.
            first_detail = str(exc) or exc.__class__.__name__

            # Only reset/retry for initiation frames (32-byte XX message 1).
            if len(packet.payload) != 32:
                self._emit_status(
                    "warning",
                    "noise_handshake_failed",
                    first_detail,
                )
                return

            self._noise.clear_session(packet.sender_id)
            try:
                response = self._noise.handle_incoming_handshake(
                    peer_id=packet.sender_id,
                    message=packet.payload,
                )
                active_client = self._active_client
                if (
                    response is not None
                    and self._loop is not None
                    and active_client is not None
                ):
                    response_bytes = response
                    client_ref = active_client

                    async def _send_handshake_response_retry() -> None:
                        out = build_packet(
                            msg_type=MessageType.NOISE_HANDSHAKE,
                            payload=response_bytes,
                            sender_peer_id_hex=self._peer_id_hex,
                            recipient_peer_id_hex=packet.sender_id,
                        )
                        await client_ref.write_gatt_char(
                            self.CHARACTERISTIC_UUID,
                            out,
                            response=False,
                        )

                    asyncio.run_coroutine_threadsafe(
                        _send_handshake_response_retry(),
                        self._loop,
                    )

                if self._noise.has_established_session(packet.sender_id):
                    recovered = bool(self._pending_dm.get(packet.sender_id))
                    self._mark_handshake_established(
                        packet.sender_id,
                        recovered=recovered,
                    )
                    self._flush_pending_dm(packet.sender_id)
                return
            except Exception as retry_exc:
                detail = str(retry_exc) or retry_exc.__class__.__name__
                self._emit_status("warning", "noise_handshake_failed", detail)

    def _handle_noise_encrypted(self, packet) -> None:
        if packet.recipient_id and packet.recipient_id != self._peer_id_hex:
            return
        try:
            decrypted = self._noise.decrypt(
                peer_id=packet.sender_id,
                ciphertext=packet.payload,
            )
        except Exception as exc:
            self._emit_status("warning", "noise_decrypt_failed", str(exc))
            self._schedule_recovery_handshake(
                packet.sender_id,
                reason="decrypt_failed",
            )
            return

        parsed = parse_private_message_payload(decrypted)
        if parsed is None:
            return
        _message_id, text = parsed
        sender = str(self._peer_map.get(packet.sender_id) or packet.sender_id)
        if self._handler:
            self._handler(
                ChatMessage(
                    sender=sender,
                    text=text,
                    channel="@dm",
                    is_private=True,
                )
            )

    def _flush_pending_dm(self, peer_id: str) -> None:
        pending = self._pending_dm.pop(peer_id, [])
        if not pending or self._loop is None:
            return

        async def _flush() -> None:
            for _message_id, text in pending:
                await self._send_direct_message(peer_id=peer_id, text=text)

        asyncio.run_coroutine_threadsafe(_flush(), self._loop)

    def _resolve_peer_target(self, target: str) -> str | None:
        token = target.strip().lstrip("@")
        if not token:
            return None
        exact = [pid for pid, name in self._peer_map.items() if name == token]
        if len(exact) == 1:
            return exact[0]
        prefix = [pid for pid in self._peer_map if pid.startswith(token)]
        if len(prefix) == 1:
            return prefix[0]
        return None

    async def _send_handshake_init(self, *, client: Any, peer_id: str) -> None:
        handshake = self._noise.initiate_handshake(peer_id)
        packet = build_packet(
            msg_type=MessageType.NOISE_HANDSHAKE,
            payload=handshake,
            sender_peer_id_hex=self._peer_id_hex,
            recipient_peer_id_hex=peer_id,
        )
        await client.write_gatt_char(self.CHARACTERISTIC_UUID, packet, response=False)
        self._handshake_deadlines[peer_id] = (
            time.monotonic() + self.HANDSHAKE_TIMEOUT_SECONDS
        )
        self._emit_status(
            "info", "dm_handshake_started", f"started handshake with {peer_id}"
        )

    async def _handshake_watchdog(self, client: Any) -> None:
        while self._running and self._active_client is client:
            await self._process_handshake_timeouts(client)
            await asyncio.sleep(0.5)

    async def _process_handshake_timeouts(self, client: Any) -> None:
        now = time.monotonic()
        expired = [
            peer_id
            for peer_id, deadline in self._handshake_deadlines.items()
            if deadline <= now
        ]
        for peer_id in expired:
            retries = self._handshake_retries.get(peer_id, 0)
            self._emit_status(
                "warning", "dm_handshake_timeout", f"timeout for {peer_id}"
            )
            if retries < self.HANDSHAKE_MAX_RETRIES:
                self._handshake_retries[peer_id] = retries + 1
                self._emit_status(
                    "info",
                    "dm_handshake_retrying",
                    f"retry {retries + 1} for {peer_id}",
                )
                self._reset_peer_session(
                    peer_id, reason="watchdog_retry", emit_status=False
                )
                try:
                    await self._send_handshake_init(client=client, peer_id=peer_id)
                except Exception as exc:
                    self._emit_status("warning", "dm_handshake_failed", str(exc))
            else:
                self._emit_status(
                    "warning",
                    "dm_handshake_failed",
                    f"exhausted retries for {peer_id}",
                )
                self._handshake_deadlines.pop(peer_id, None)

    def _mark_handshake_established(self, peer_id: str, *, recovered: bool) -> None:
        self._handshake_deadlines.pop(peer_id, None)
        self._handshake_retries.pop(peer_id, None)
        code = "dm_handshake_recovered" if recovered else "dm_handshake_established"
        self._emit_status("info", code, f"session established with {peer_id}")

    def _reset_peer_session(
        self, peer_id: str, *, reason: str, emit_status: bool
    ) -> None:
        self._noise.clear_session(peer_id)
        self._handshake_deadlines.pop(peer_id, None)
        self._handshake_retries.pop(peer_id, None)
        if emit_status:
            self._emit_status("info", "dm_session_reset", f"{peer_id}: {reason}")

    def _reset_all_sessions(self, *, reason: str, emit_status: bool) -> None:
        self._noise.clear_all_sessions()
        self._handshake_deadlines.clear()
        self._handshake_retries.clear()
        self._last_recovery_attempt.clear()
        self._pending_dm.clear()
        if emit_status:
            self._emit_status(
                "info", "dm_session_reset", f"all sessions reset: {reason}"
            )

    def _schedule_recovery_handshake(self, peer_id: str, *, reason: str) -> None:
        now = time.monotonic()
        last = self._last_recovery_attempt.get(peer_id, 0.0)
        if now - last < self.RECOVERY_COOLDOWN_SECONDS:
            return
        self._last_recovery_attempt[peer_id] = now
        self._reset_peer_session(peer_id, reason=reason, emit_status=True)

        if self._loop is None or self._active_client is None:
            return

        client = self._active_client

        async def _recover() -> None:
            try:
                await self._send_handshake_init(client=client, peer_id=peer_id)
            except Exception as exc:
                self._emit_status("warning", "dm_handshake_failed", str(exc))

        asyncio.run_coroutine_threadsafe(_recover(), self._loop)

    def _emit_status(self, level: str, code: str, detail: str) -> None:
        if self._status_handler is None:
            return
        self._status_handler(ClientStatus(level=level, code=code, detail=detail))

    def _register_disconnect_callback(
        self,
        client: Any,
        callback: Callable[[Any], None],
    ) -> bool:
        setter = getattr(client, "set_disconnected_callback", None)
        if not callable(setter):
            return False
        setter(callback)
        return True

    async def _poll_disconnect_state(
        self,
        client: Any,
        disconnected_event: asyncio.Event,
        stop_event: asyncio.Event,
        poll_interval: float = 0.5,
    ) -> None:
        while (
            self._running
            and not stop_event.is_set()
            and not disconnected_event.is_set()
        ):
            is_connected = bool(getattr(client, "is_connected", True))
            if not is_connected:
                disconnected_event.set()
                return
            await asyncio.sleep(poll_interval)


def create_client(
    identity: IdentityKeyPair | None = None,
    dedupe_cache: MessageDedupCache | None = None,
) -> BitChatClient:
    try:
        import bleak  # noqa: F401

        return BleBitChatClient(identity=identity, dedupe_cache=dedupe_cache)
    except Exception:
        return NullBitChatClient()
