"""Update an organization's metadata."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import Organization
from ...domain.exceptions import UnknownOrganization
from ...domain.ports import OrganizationRepository
from ...domain.value_objects import OrgId


@dataclass(slots=True)
class UpdateOrganizationUseCase:
    """Update an organization's display name.

    The slug is intentionally immutable (changing it would break URLs
    and ``X-Organization-Id`` headers in flight). Pass ``name=None`` to
    leave the name unchanged.
    """

    organization_repo: OrganizationRepository

    async def execute(
        self,
        org_id: OrgId,
        *,
        name: str | None = None,
    ) -> Organization:
        if await self.organization_repo.get(org_id) is None:
            raise UnknownOrganization(f"organization {org_id} not found")
        return await self.organization_repo.update(org_id, name=name)
