"""Enable/disable a service for an organization (SaaS governance)."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import OrganizationService
from ...domain.exceptions import ServiceNotSaaSAvailable, UnknownService
from ...domain.ports import (
    OrganizationServiceRepository,
    ServiceRepository,
)
from ...domain.value_objects import OrgId, ServiceName


@dataclass(slots=True)
class SetOrganizationServiceUseCase:
    """Toggle a service for an organization, enforcing vendor SaaS policy.

    This is what a platform-admin API endpoint calls. Enabling is rejected
    with :class:`ServiceNotSaaSAvailable` unless the service is marked
    ``saas_available`` by the vendor (via ``pkg-auth-sync-services``), which
    is how the package owner keeps the client from offering arbitrary
    services as SaaS. Disabling is always allowed.
    """

    service_repo: ServiceRepository
    org_service_repo: OrganizationServiceRepository

    async def execute(
        self,
        *,
        org_id: OrgId,
        service_name: ServiceName,
        enabled: bool,
    ) -> OrganizationService | None:
        service = await self.service_repo.get(service_name)
        if service is None:
            raise UnknownService(f"service {service_name} is not registered")

        if not enabled:
            await self.org_service_repo.disable(org_id, service_name)
            return None

        if not service.saas_available:
            raise ServiceNotSaaSAvailable(
                f"service {service_name} is not available to offer as SaaS"
            )
        return await self.org_service_repo.enable(
            org_id, service_name, source="manual"
        )
