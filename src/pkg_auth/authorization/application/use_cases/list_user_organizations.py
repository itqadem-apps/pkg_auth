"""List the organizations a user belongs to."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import Organization
from ...domain.ports import OrganizationRepository
from ...domain.value_objects import UserId


@dataclass(slots=True)
class ListUserOrganizationsUseCase:
    """Return the organizations a user has any membership in.

    Used by "switch organization" UIs in client apps.
    """

    organization_repo: OrganizationRepository

    async def execute(self, user_id: UserId) -> list[Organization]:
        return await self.organization_repo.list_for_user(user_id)
