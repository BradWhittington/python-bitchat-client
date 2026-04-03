import time
from collections import OrderedDict
from typing import Protocol


class MessageDedupCache(Protocol):
    def is_duplicate(self, key: str) -> bool: ...

    def mark_seen(self, key: str) -> None: ...


class LruTtlDedupeCache:
    def __init__(self, *, max_entries: int = 1000, ttl_seconds: float = 300.0) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be > 0")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._entries: OrderedDict[str, float] = OrderedDict()

    def is_duplicate(self, key: str) -> bool:
        self._prune_expired()
        if key not in self._entries:
            return False
        self._entries.move_to_end(key)
        return True

    def mark_seen(self, key: str) -> None:
        self._prune_expired()
        self._entries[key] = time.monotonic()
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def _prune_expired(self) -> None:
        now = time.monotonic()
        while self._entries:
            _, seen_at = next(iter(self._entries.items()))
            if now - seen_at <= self._ttl_seconds:
                break
            self._entries.popitem(last=False)
