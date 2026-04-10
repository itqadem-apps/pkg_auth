"""Create an organization."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import Organization
from ...domain.ports import OrganizationRepository


@dataclass(slots=True)
class CreateOrganizationUseCase:
    """Create a new organization.

    Slug uniqueness is enforced at the database level by a UNIQUE
    constraint; the repository may raise a conflict error which the
    integration layer can map to HTTP 409.
    """

    organization_repo: OrganizationRepository

    async def execute(self, *, slug: str, name: str) -> Organization:
        return await self.organization_repo.create(slug=slug, name=name)
