"""Pluggable cache layer for the ACL hot path.

Public API:

    Cache                       — Protocol port (bytes-in/bytes-out)
    InMemoryTTLCache            — zero-deps in-process LRU + TTL cache
    RedisCache                  — async redis backend (cache-redis extra)
    CachedMembershipRepository  — decorator wrapping any MembershipRepository
"""
from __future__ import annotations

from .decorators import CachedMembershipRepository
from .memory import InMemoryTTLCache
from .protocol import Cache

__all__ = [
    "Cache",
    "InMemoryTTLCache",
    "CachedMembershipRepository",
]

# RedisCache is opt-in via the cache-redis extra. Don't import it
# eagerly so users without redis installed don't see import errors.
try:
    from .redis import RedisCache  # noqa: F401
    __all__.append("RedisCache")
except ImportError:  # pragma: no cover
    pass
