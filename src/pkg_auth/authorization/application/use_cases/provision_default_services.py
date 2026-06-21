"""Provision the default (auto-provision) services for an organization."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.ports import (
    OrganizationServiceRepository,
    ServiceRepository,
)
from ...domain.value_objects import OrgId


@dataclass(slots=True)
class ProvisionDefaultServicesUseCase:
    """Enable every ``auto_provision`` service for an organization.

    Called on organization creation (wired into pkg_auth's own
    :class:`CreateOrganizationUseCase`; Mode A services call it from their
    own org-creation flow). Idempotent — re-running only re-enables the same
    default set with ``source="auto"``.

    Under the default-deny service guard, an org that never runs this (and is
    never granted services manually) resolves to zero permissions for normal
    members. Mark core services (e.g. ``users``) ``auto_provision=True`` so
    every org gets them.
    """

    service_repo: ServiceRepository
    org_service_repo: OrganizationServiceRepository

    async def execute(self, *, org_id: OrgId) -> list[str]:
        services = await self.service_repo.list_all()
        names = [s.name for s in services if s.auto_provision]
        if names:
            await self.org_service_repo.bulk_enable(
                org_id, names, source="auto"
            )
        return [str(n) for n in names]
