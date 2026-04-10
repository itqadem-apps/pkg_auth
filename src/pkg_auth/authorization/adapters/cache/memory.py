"""In-process LRU + TTL cache (zero new dependencies)."""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass(slots=True)
class InMemoryTTLCache:
    """Per-process LRU cache with per-entry TTL.

    Suitable for single-replica services or when freshness can tolerate
    per-pod divergence. For horizontally-scaled services that need
    cache coherence, use :class:`RedisCache` instead.

    The cache is async-safe via an internal :class:`asyncio.Lock` —
    multiple coroutines can hit it concurrently without races.
    """

    max_entries: int = 10_000
    _store: OrderedDict[str, tuple[bytes, float]] = field(
        default_factory=OrderedDict
    )
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def get(self, key: str) -> bytes | None:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at < time.monotonic():
                # Expired — drop and miss
                self._store.pop(key, None)
                return None
            # LRU touch
            self._store.move_to_end(key)
            return value

    async def set(
        self, key: str, value: bytes, *, ttl_seconds: int
    ) -> None:
        async with self._lock:
            expires_at = time.monotonic() + ttl_seconds
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, expires_at)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def invalidate_prefix(self, prefix: str) -> None:
        async with self._lock:
            doomed = [k for k in self._store if k.startswith(prefix)]
            for k in doomed:
                self._store.pop(k, None)
