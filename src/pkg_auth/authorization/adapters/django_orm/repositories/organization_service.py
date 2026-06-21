"""Django ORM implementation of OrganizationServiceRepository."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from ....domain.entities import OrganizationService
from ....domain.value_objects import OrgId, ServiceName
from ..models import OrganizationService as DefaultOrganizationServiceModel


def _to_domain(row) -> OrganizationService:
    return OrganizationService(
        organization_id=OrgId(row.organization_id),
        service_name=ServiceName(row.service_name),
        enabled=bool(row.enabled),
        source=row.source,
        granted_at=row.granted_at,
    )


@dataclass(slots=True)
class DjangoOrganizationServiceRepository:
    model: type = field(default=DefaultOrganizationServiceModel)

    async def list_enabled_service_names(self, org_id: OrgId) -> set[str]:
        return {
            row.service_name
            async for row in self.model.objects.filter(
                organization_id=org_id.value, enabled=True
            ).only("service_name")
        }

    async def get(
        self, org_id: OrgId, service_name: ServiceName
    ) -> OrganizationService | None:
        row = await self.model.objects.filter(
            organization_id=org_id.value, service_name=str(service_name)
        ).afirst()
        return _to_domain(row) if row is not None else None

    async def enable(
        self, org_id: OrgId, service_name: ServiceName, *, source: str
    ) -> OrganizationService:
        row, _ = await self.model.objects.aupdate_or_create(
            organization_id=org_id.value,
            service_name=str(service_name),
            defaults={"enabled": True, "source": source},
        )
        return _to_domain(row)

    async def disable(
        self, org_id: OrgId, service_name: ServiceName
    ) -> None:
        await self.model.objects.filter(
            organization_id=org_id.value, service_name=str(service_name)
        ).adelete()

    async def bulk_enable(
        self,
        org_id: OrgId,
        service_names: Sequence[ServiceName],
        *,
        source: str,
    ) -> None:
        for name in service_names:
            await self.model.objects.aupdate_or_create(
                organization_id=org_id.value,
                service_name=str(name),
                defaults={"enabled": True, "source": source},
            )
