# Caching

The authorization hot path (`load_auth_context`) runs on every protected request. Without caching, this is a Postgres query (joined across `memberships`, `roles`, `role_permissions`, `permissions`). The cache layer eliminates repeated queries for the same `(user, org)` pair within a short TTL window.

## Architecture

```
CachedMembershipRepository  (decorator — implements MembershipRepository)
├── inner: SqlAlchemyMembershipRepository  (the real DB)
└── cache: Cache  (Protocol — InMemoryTTLCache or RedisCache)
```

## Usage

```python
from pkg_auth.authorization.adapters.cache import (
    CachedMembershipRepository, InMemoryTTLCache,
)

inner = SqlAlchemyMembershipRepository(session_factory=session_factory)
cache = InMemoryTTLCache(max_entries=10_000)
membership_repo = CachedMembershipRepository(
    inner=inner, cache=cache, ttl_seconds=30,
)
```

For Redis:

```python
import redis.asyncio as redis
from pkg_auth.authorization.adapters.cache import (
    CachedMembershipRepository, RedisCache,
)

client = redis.from_url("redis://localhost:6379/0")
membership_repo = CachedMembershipRepository(
    inner=SqlAlchemyMembershipRepository(session_factory=session_factory),
    cache=RedisCache(client=client, namespace="pkg_auth:acl"),
    ttl_seconds=60,
)
```

## Cache invalidation

| Operation | Invalidation |
|---|---|
| `upsert` (membership) | Auto — the decorator deletes the `(user, org)` key |
| `delete` (membership) | Auto — same |
| `update_role` (perms change) | **Manual** — the calling use case must call `cache.invalidate_prefix("auth_ctx:")` |

Role-level changes affect potentially many cached entries. The package does NOT auto-invalidate them because guessing wrong would silently serve stale perms. Document this in your service's role-update endpoint.

## Custom backends

Implement the `Cache` Protocol (bytes-in/bytes-out: `get`, `set`, `delete`, `invalidate_prefix`) and pass your implementation to `CachedMembershipRepository`.

## CORS

If your service uses CORS middleware, add `X-Organization-Id` to `allow_headers` — otherwise preflight requests for the org header will be blocked.
