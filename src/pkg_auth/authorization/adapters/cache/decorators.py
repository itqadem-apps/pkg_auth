"""CachedMembershipRepository — decorator wrapping any MembershipRepository.

Implements the same Protocol as the underlying repository, so it can be
passed into use cases anywhere ``MembershipRepository`` is expected. The
hot-path :meth:`load_auth_context` is the one that actually consults the
cache; other methods proxy through and invalidate the affected key on
writes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from ...domain.entities import AuthContext, Membership
from ...domain.ports import MembershipRepository
from ...domain.value_objects import OrgId, RoleId, RoleName, UserId
from .protocol import Cache

DEFAULT_TTL_SECONDS = 30


def _auth_context_key(user_id: UserId, org_id: OrgId) -> str:
    return f"auth_ctx:{user_id}:{org_id}"


def _serialize_auth_context(ctx: AuthContext) -> bytes:
    payload = {
        "user_id": str(ctx.user_id.value),
        "organization_id": str(ctx.organization_id.value),
        "role_name": str(ctx.role_name),
        "perms": sorted(ctx.perms),
    }
    return json.dumps(payload).encode("utf-8")


def _deserialize_auth_context(blob: bytes) -> AuthContext:
    payload = json.loads(blob.decode("utf-8"))
    return AuthContext(
        user_id=UserId(UUID(payload["user_id"])),
        organization_id=OrgId(UUID(payload["organization_id"])),
        role_name=RoleName(payload["role_name"]),
        perms=frozenset(payload["perms"]),
    )


@dataclass(slots=True)
class CachedMembershipRepository:
    """Cache-decorating wrapper around a real ``MembershipRepository``.

    Usage::

        inner = SqlAlchemyMembershipRepository(session_factory=...)
        cache = InMemoryTTLCache(max_entries=10_000)
        membership_repo = CachedMembershipRepository(
            inner=inner, cache=cache, ttl_seconds=30,
        )

    Cache invalidation:
        - :meth:`upsert` and :meth:`delete` invalidate the affected
          ``(user_id, org_id)`` key.
        - **Role-level changes** (e.g. updating a role's permission set)
          affect many cached entries and are NOT auto-invalidated. The
          calling use case must call ``cache.invalidate_prefix("auth_ctx:")``
          after the role mutation. The package documents this convention
          in ``docs/Caching.md``; we deliberately don't hide it because
          guessing wrong here would silently serve stale perms.
    """

    inner: MembershipRepository
    cache: Cache
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> Membership | None:
        return await self.inner.get(user_id, org_id)

    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> Membership:
        result = await self.inner.upsert(
            user_id=user_id,
            org_id=org_id,
            role_id=role_id,
            status=status,
        )
        await self.cache.delete(_auth_context_key(user_id, org_id))
        return result

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        await self.inner.delete(user_id, org_id)
        await self.cache.delete(_auth_context_key(user_id, org_id))

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        cache_key = _auth_context_key(user_id, org_id)
        blob = await self.cache.get(cache_key)
        if blob is not None:
            return _deserialize_auth_context(blob)
        ctx = await self.inner.load_auth_context(user_id, org_id)
        if ctx is not None:
            await self.cache.set(
                cache_key,
                _serialize_auth_context(ctx),
                ttl_seconds=self.ttl_seconds,
            )
        return ctx

    async def list_for_user(self, user_id: UserId) -> list[Membership]:
        return await self.inner.list_for_user(user_id)
