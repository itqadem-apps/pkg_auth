"""Django ORM implementation of MembershipRepository (multi-role aware)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ....domain.entities import AuthContext, Membership as DomainMembership
from ....domain.value_objects import (
    OrgId,
    RoleId,
    RoleName,
    UserId,
)
from ..models import Membership as DefaultMembershipModel
from ..models import Role as DefaultRoleModel


def _to_domain(row, role_name: str) -> DomainMembership:
    return DomainMembership(
        id=row.id,
        user_id=UserId(row.user_id),
        organization_id=OrgId(row.organization_id),
        role_id=RoleId(row.role_id),
        role_name=RoleName(role_name),
        status=row.status,
        joined_at=row.joined_at,
    )


@dataclass(slots=True)
class DjangoMembershipRepository:
    """Multi-role per (user, org). Storage uniqueness is on
    ``(user_id, organization_id, role_id)`` and ``load_auth_context``
    aggregates the union of all active memberships."""

    model: type = field(default=DefaultMembershipModel)
    role_model: type = field(default=DefaultRoleModel)

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> DomainMembership | None:
        row = await (
            self.model.objects
            .select_related("role")
            .filter(user_id=user_id.value, organization_id=org_id.value)
            .afirst()
        )
        if row is None:
            return None
        return _to_domain(row, row.role.name)

    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> DomainMembership:
        now = datetime.now(timezone.utc)
        row, created = await self.model.objects.aupdate_or_create(
            user_id=user_id.value,
            organization_id=org_id.value,
            role_id=role_id.value,
            defaults={
                "status": status,
                "updated_at": now,
            },
        )
        if created:
            row.joined_at = now
            row.created_at = now
            await row.asave(update_fields=["joined_at", "created_at"])
        # Re-fetch with role for role_name
        row = await self.model.objects.select_related("role").aget(id=row.id)
        return _to_domain(row, row.role.name)

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        # Multi-role: removes ALL memberships for (user, org).
        await self.model.objects.filter(
            user_id=user_id.value, organization_id=org_id.value,
        ).adelete()

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        rows = (
            self.model.objects
            .select_related("role")
            .prefetch_related("role__permissions")
            .filter(
                user_id=user_id.value,
                organization_id=org_id.value,
                status="active",
            )
        )
        role_names: set[str] = set()
        perms: set[str] = set()
        any_active = False
        async for row in rows:
            any_active = True
            role_names.add(row.role.name)
            async for k in row.role.permissions.all().values_list("key", flat=True):
                perms.add(k)
        if not any_active:
            return None
        return AuthContext(
            user_id=user_id,
            organization_id=org_id,
            role_names=frozenset(role_names),
            perms=frozenset(perms),
        )

    async def list_for_user(self, user_id: UserId) -> list[DomainMembership]:
        rows = self.model.objects.select_related("role").filter(
            user_id=user_id.value
        )
        return [_to_domain(r, r.role.name) async for r in rows]
