"""Resolve an :class:`AuthContext` for a (user, organization) pair."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import AuthContext
from ...domain.exceptions import NotAMember
from ...domain.ports import (
    MembershipRepository,
    OrganizationServiceRepository,
    PermissionCatalogRepository,
)
from ...domain.value_objects import OrgId, UserId


@dataclass(slots=True)
class ResolveAuthContextUseCase:
    """Hot-path use case: load the AuthContext for a request.

    Called once per protected request by the FastAPI / Django / Strawberry
    deps. The membership repository is responsible for joining the role
    and its permissions in a single query so this is a single network
    round-trip to Postgres (or a hit on the cache decorator).

    **Service guard.** When ``org_service_repo`` and ``catalog_repo`` are
    wired, the resolved permissions are filtered down to the services the
    organization actually has enabled (**default-deny**: a perm whose owning
    service is not enabled for the org is dropped). The platform org — when
    its id is passed as ``platform_org_id`` — bypasses the guard entirely so
    platform admins keep all permissions. Leaving the guard repos unset
    preserves the pre-guard behavior (no filtering), which lets services
    adopt the guard incrementally.
    """

    membership_repo: MembershipRepository
    org_service_repo: OrganizationServiceRepository | None = None
    catalog_repo: PermissionCatalogRepository | None = None
    platform_org_id: OrgId | None = None

    async def execute(self, user_id: UserId, org_id: OrgId) -> AuthContext:
        ctx = await self.membership_repo.load_auth_context(user_id, org_id)
        if ctx is None:
            raise NotAMember(
                f"user {user_id} is not a member of org {org_id}"
            )
        return await self._apply_service_guard(ctx, org_id)

    async def _apply_service_guard(
        self, ctx: AuthContext, org_id: OrgId
    ) -> AuthContext:
        if self.org_service_repo is None or self.catalog_repo is None:
            return ctx  # guard not wired
        if self.platform_org_id is not None and org_id == self.platform_org_id:
            return ctx  # platform admins bypass the guard
        if not ctx.perms:
            return ctx

        enabled = await self.org_service_repo.list_enabled_service_names(org_id)
        service_map = await self.catalog_repo.get_service_map()
        allowed = frozenset(
            perm for perm in ctx.perms if service_map.get(perm) in enabled
        )
        if allowed == ctx.perms:
            return ctx
        return AuthContext(
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            role_names=ctx.role_names,
            perms=allowed,
        )
