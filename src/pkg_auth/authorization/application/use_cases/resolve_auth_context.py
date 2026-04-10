"""Resolve an :class:`AuthContext` for a (user, organization) pair."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import AuthContext
from ...domain.exceptions import NotAMember
from ...domain.ports import MembershipRepository
from ...domain.value_objects import OrgId, UserId


@dataclass(slots=True)
class ResolveAuthContextUseCase:
    """Hot-path use case: load the AuthContext for a request.

    Called once per protected request by the FastAPI / Django / Strawberry
    deps. The membership repository is responsible for joining the role
    and its permissions in a single query so this is a single network
    round-trip to Postgres (or a hit on the cache decorator).
    """

    membership_repo: MembershipRepository

    async def execute(self, user_id: UserId, org_id: OrgId) -> AuthContext:
        ctx = await self.membership_repo.load_auth_context(user_id, org_id)
        if ctx is None:
            raise NotAMember(
                f"user {user_id} is not a member of org {org_id}"
            )
        return ctx
