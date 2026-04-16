"""Resolve a local user from a Keycloak JWT identity (read-only, Mode B)."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import User
from ...domain.exceptions import UserNotProvisioned
from ...domain.ports import UserRepository


@dataclass(slots=True)
class ResolveUserFromJwtUseCase:
    """Look up a local ``users`` row by Keycloak ``sub`` without writing.

    Use this in Mode B (consuming) services whose ``ACL_DATABASE_URL``
    points at a Mode A-owned database. Writing the ``users`` table is
    the source-of-truth service's job; a Mode B consumer that has never
    seen a given ``sub`` means the SoT hasn't provisioned them yet —
    which is a 403, not a signal to insert.

    Raises :class:`UserNotProvisioned` when no row exists for ``sub``.
    Integration layers map that to HTTP 403.
    """

    user_repo: UserRepository

    async def execute(self, *, sub: str) -> User:
        user = await self.user_repo.get_by_keycloak_sub(sub)
        if user is None:
            raise UserNotProvisioned(
                f"No local user for Keycloak sub {sub!r}; "
                "source-of-truth service has not provisioned this user yet."
            )
        return user
