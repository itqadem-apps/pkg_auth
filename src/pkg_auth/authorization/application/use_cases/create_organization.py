"""Create an organization."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import Organization
from ...domain.ports import (
    OrganizationRepository,
    OrganizationServiceRepository,
    ServiceRepository,
)
from .provision_default_services import ProvisionDefaultServicesUseCase


@dataclass(slots=True)
class CreateOrganizationUseCase:
    """Create a new organization.

    Slug uniqueness is enforced at the database level by a UNIQUE
    constraint; the repository may raise a conflict error which the
    integration layer can map to HTTP 409.

    When ``service_repo`` and ``org_service_repo`` are wired, every
    ``auto_provision`` service is enabled for the new org (so default-deny
    members still get the default product surfaces). Leaving them unset
    skips provisioning — Mode A services that own their own create flow call
    :class:`ProvisionDefaultServicesUseCase` themselves instead.
    """

    organization_repo: OrganizationRepository
    service_repo: ServiceRepository | None = None
    org_service_repo: OrganizationServiceRepository | None = None

    async def execute(self, *, slug: str, name: str) -> Organization:
        org = await self.organization_repo.create(slug=slug, name=name)
        if self.service_repo is not None and self.org_service_repo is not None:
            await ProvisionDefaultServicesUseCase(
                service_repo=self.service_repo,
                org_service_repo=self.org_service_repo,
            ).execute(org_id=org.id)
        return org
