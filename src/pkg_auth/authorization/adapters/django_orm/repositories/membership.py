"""Django ORM implementation of MembershipRepository."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ....domain.entities import AuthContext, Membership as DomainMembership
from ....domain.value_objects import (
    OrgId,
    RoleId,
    RoleName,
    UserId,
)
from ..models import Membership as MembershipModel


def _to_domain(row: MembershipModel, role_name: str) -> DomainMembership:
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
    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> DomainMembership | None:
        try:
            row = await MembershipModel.objects.select_related("role").aget(
                user_id=int(user_id),
                organization_id=int(org_id),
            )
        except MembershipModel.DoesNotExist:
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
        row, created = await MembershipModel.objects.aupdate_or_create(
            user_id=int(user_id),
            organization_id=int(org_id),
            defaults={
                "role_id": int(role_id),
                "status": status,
                "updated_at": now,
                **({"joined_at": now, "created_at": now} if False else {}),
            },
        )
        if created:
            row.joined_at = now
            row.created_at = now
            await row.asave(update_fields=["joined_at", "created_at"])
        # Re-fetch with role for role_name
        row = await MembershipModel.objects.select_related("role").aget(id=row.id)
        return _to_domain(row, row.role.name)

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        await MembershipModel.objects.filter(
            user_id=int(user_id), organization_id=int(org_id)
        ).adelete()

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        try:
            row = await MembershipModel.objects.select_related(
                "role"
            ).prefetch_related("role__permissions").aget(
                user_id=int(user_id),
                organization_id=int(org_id),
                status="active",
            )
        except MembershipModel.DoesNotExist:
            return None
        perm_keys = [
            k async for k in row.role.permissions.all().values_list("key", flat=True)
        ]
        return AuthContext(
            user_id=UserId(row.user_id),
            organization_id=OrgId(row.organization_id),
            role_name=RoleName(row.role.name),
            perms=frozenset(perm_keys),
        )

    async def list_for_user(self, user_id: UserId) -> list[DomainMembership]:
        rows = MembershipModel.objects.select_related("role").filter(
            user_id=int(user_id)
        )
        return [_to_domain(r, r.role.name) async for r in rows]
