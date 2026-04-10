"""Delete an organization (and cascade memberships, roles)."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.ports import OrganizationRepository
from ...domain.value_objects import OrgId


@dataclass(slots=True)
class DeleteOrganizationUseCase:
    """Idempotently delete an organization.

    Cascades to memberships and org-scoped roles via DB-level
    ``ON DELETE CASCADE``. Calling on a non-existent org is a no-op.
    """

    organization_repo: OrganizationRepository

    async def execute(self, org_id: OrgId) -> None:
        await self.organization_repo.delete(org_id)
