"""Django ORM implementation of OrganizationRepository."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ....domain.entities import Organization as DomainOrganization
from ....domain.value_objects import OrgId, UserId
from ..models import Organization as OrganizationModel


def _to_domain(row: OrganizationModel) -> DomainOrganization:
    return DomainOrganization(
        id=OrgId(row.id),
        slug=row.slug,
        name=row.name,
        created_at=row.created_at,
    )


@dataclass(slots=True)
class DjangoOrganizationRepository:
    async def get(self, org_id: OrgId) -> DomainOrganization | None:
        try:
            row = await OrganizationModel.objects.aget(id=int(org_id))
        except OrganizationModel.DoesNotExist:
            return None
        return _to_domain(row)

    async def get_by_slug(self, slug: str) -> DomainOrganization | None:
        try:
            row = await OrganizationModel.objects.aget(slug=slug)
        except OrganizationModel.DoesNotExist:
            return None
        return _to_domain(row)

    async def create(self, *, slug: str, name: str) -> DomainOrganization:
        now = datetime.now(timezone.utc)
        row = await OrganizationModel.objects.acreate(
            slug=slug, name=name, created_at=now, updated_at=now,
        )
        return _to_domain(row)

    async def update(
        self, org_id: OrgId, *, name: str | None
    ) -> DomainOrganization:
        row = await OrganizationModel.objects.aget(id=int(org_id))
        if name is not None:
            row.name = name
            row.updated_at = datetime.now(timezone.utc)
            await row.asave(update_fields=["name", "updated_at"])
        return _to_domain(row)

    async def delete(self, org_id: OrgId) -> None:
        await OrganizationModel.objects.filter(id=int(org_id)).adelete()

    async def list_for_user(self, user_id: UserId) -> list[DomainOrganization]:
        rows = OrganizationModel.objects.filter(
            memberships__user_id=int(user_id)
        ).order_by("id")
        return [_to_domain(r) async for r in rows]
