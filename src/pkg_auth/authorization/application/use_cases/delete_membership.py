"""Remove a membership row."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.ports import MembershipRepository
from ...domain.value_objects import OrgId, UserId


@dataclass(slots=True)
class DeleteMembershipUseCase:
    """Idempotently remove a user's membership in an organization.

    Calling on a non-existent membership is a no-op (does not raise),
    so this can be safely retried.
    """

    membership_repo: MembershipRepository

    async def execute(self, *, user_id: UserId, org_id: OrgId) -> None:
        await self.membership_repo.delete(user_id, org_id)
