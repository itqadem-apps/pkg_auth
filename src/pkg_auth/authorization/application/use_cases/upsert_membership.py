"""Create or update a membership row."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import Membership
from ...domain.exceptions import (
    UnknownOrganization,
    UnknownRole,
    UnknownUser,
)
from ...domain.ports import (
    MembershipRepository,
    OrganizationRepository,
    RoleRepository,
    UserRepository,
)
from ...domain.value_objects import OrgId, RoleId, UserId


@dataclass(slots=True)
class UpsertMembershipUseCase:
    """Idempotently grant a user a role in an organization.

    Pre-flights the user, organization, and role to surface clean
    domain exceptions instead of leaking adapter-level FK violations.
    """

    user_repo: UserRepository
    organization_repo: OrganizationRepository
    role_repo: RoleRepository
    membership_repo: MembershipRepository

    async def execute(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str = "active",
    ) -> Membership:
        if await self.user_repo.get_by_id(user_id) is None:
            raise UnknownUser(f"user {user_id} not found")
        if await self.organization_repo.get(org_id) is None:
            raise UnknownOrganization(f"organization {org_id} not found")
        if await self.role_repo.get(role_id) is None:
            raise UnknownRole(f"role {role_id} not found")

        return await self.membership_repo.upsert(
            user_id=user_id,
            org_id=org_id,
            role_id=role_id,
            status=status,
        )
