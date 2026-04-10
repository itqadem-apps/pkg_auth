"""Async Redis cache backend (cache-redis extra)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

try:
    import redis.asyncio as redis_asyncio  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.authorization.adapters.cache.redis requires the redis "
        "package. Install with: pip install pkg-auth[cache-redis]"
    ) from exc

if TYPE_CHECKING:
    from redis.asyncio import Redis


@dataclass(slots=True)
class RedisCache:
    """Async Redis-backed :class:`Cache` implementation.

    The Redis client is injected — services build their own
    ``redis.asyncio.Redis`` (with auth, sentinel, etc.) and hand it to
    the cache. The cache itself only knows how to ``GET`` / ``SET`` /
    ``DEL`` / ``SCAN``.

    All keys are namespaced by ``namespace`` so this cache can coexist
    with other Redis users in the same database without collision.
    """

    client: "Redis"
    namespace: str = "pkg_auth:acl"
    scan_count: int = 500

    def _k(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    async def get(self, key: str) -> bytes | None:
        return await self.client.get(self._k(key))

    async def set(
        self, key: str, value: bytes, *, ttl_seconds: int
    ) -> None:
        await self.client.set(self._k(key), value, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        await self.client.delete(self._k(key))

    async def invalidate_prefix(self, prefix: str) -> None:
        match = f"{self._k(prefix)}*"
        cursor = 0
        while True:
            cursor, keys = await self.client.scan(
                cursor=cursor, match=match, count=self.scan_count
            )
            if keys:
                await self.client.delete(*keys)
            if cursor == 0:
                break
