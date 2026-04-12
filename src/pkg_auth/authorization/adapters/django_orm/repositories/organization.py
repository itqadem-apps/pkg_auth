"""Django ORM implementation of OrganizationRepository."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ....domain.entities import Organization as DomainOrganization
from ....domain.value_objects import OrgId, UserId
from ..models import Membership as DefaultMembershipModel
from ..models import Organization as DefaultOrganizationModel


def _to_domain(row) -> DomainOrganization:
    return DomainOrganization(
        id=OrgId(row.id),
        slug=row.slug,
        name=row.name,
        created_at=row.created_at,
    )


@dataclass(slots=True)
class DjangoOrganizationRepository:
    """``model`` and ``membership_model`` are injectable so consuming
    services can swap in their own concrete classes (extending the
    abstract mixins). Defaults are the package's managed=False mirrors."""

    model: type = field(default=DefaultOrganizationModel)
    membership_model: type = field(default=DefaultMembershipModel)

    async def get(self, org_id: OrgId) -> DomainOrganization | None:
        try:
            row = await self.model.objects.aget(id=org_id.value)
        except self.model.DoesNotExist:
            return None
        return _to_domain(row)

    async def get_by_slug(self, slug: str) -> DomainOrganization | None:
        try:
            row = await self.model.objects.aget(slug=slug)
        except self.model.DoesNotExist:
            return None
        return _to_domain(row)

    async def create(self, *, slug: str, name: str) -> DomainOrganization:
        now = datetime.now(timezone.utc)
        row = await self.model.objects.acreate(
            slug=slug, name=name, created_at=now, updated_at=now,
        )
        return _to_domain(row)

    async def update(
        self, org_id: OrgId, *, name: str | None
    ) -> DomainOrganization:
        row = await self.model.objects.aget(id=org_id.value)
        if name is not None:
            row.name = name
            row.updated_at = datetime.now(timezone.utc)
            await row.asave(update_fields=["name", "updated_at"])
        return _to_domain(row)

    async def delete(self, org_id: OrgId) -> None:
        await self.model.objects.filter(id=org_id.value).adelete()

    async def list_for_user(self, user_id: UserId) -> list[DomainOrganization]:
        # Distinct because a multi-role user has multiple membership rows per org.
        rows = (
            self.model.objects
            .filter(memberships__user_id=user_id.value)
            .distinct()
            .order_by("id")
        )
        return [_to_domain(r) async for r in rows]
