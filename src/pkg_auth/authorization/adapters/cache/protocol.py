"""Cache port — abstract bytes-in/bytes-out cache."""
from __future__ import annotations

from typing import Protocol


class Cache(Protocol):
    """Bytes-keyed cache abstraction.

    Implementations are bytes-in / bytes-out: serialization is the
    decorator's responsibility, not the cache's. This keeps the protocol
    portable across in-memory, Redis, memcached, etc.
    """

    async def get(self, key: str) -> bytes | None:
        """Return the cached value, or ``None`` if missing or expired."""
        ...

    async def set(
        self, key: str, value: bytes, *, ttl_seconds: int
    ) -> None:
        """Store ``value`` at ``key`` with the given TTL in seconds."""
        ...

    async def delete(self, key: str) -> None:
        """Remove ``key`` if present. No-op if missing."""
        ...

    async def invalidate_prefix(self, prefix: str) -> None:
        """Remove every key starting with ``prefix``.

        Used for bulk invalidation when role-level changes affect many
        cached AuthContexts at once. Implementations may use SCAN+DEL
        on Redis or a single dict comprehension in memory.
        """
        ...
