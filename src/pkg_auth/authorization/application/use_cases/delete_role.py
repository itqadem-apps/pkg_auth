"""Delete a role (and cascade-detach any memberships)."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.ports import RoleRepository
from ...domain.value_objects import RoleId


@dataclass(slots=True)
class DeleteRoleUseCase:
    """Idempotently delete a role.

    The DB schema uses ``ON DELETE RESTRICT`` for membership FKs to the
    role; if any memberships still reference this role, the repository
    raises a conflict error which the integration layer can map to
    HTTP 409. Callers must reassign or remove memberships first.
    """

    role_repo: RoleRepository

    async def execute(self, role_id: RoleId) -> None:
        await self.role_repo.delete(role_id)
