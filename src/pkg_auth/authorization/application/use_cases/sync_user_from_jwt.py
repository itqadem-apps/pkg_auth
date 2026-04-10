"""Sync a user record from a Keycloak JWT identity (lazy upsert)."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import User
from ...domain.ports import UserRepository


@dataclass(slots=True)
class SyncUserFromJwtUseCase:
    """Upsert a row in ``acl.users`` from JWT identity claims.

    Called by integration deps the first time they see a JWT for a given
    Keycloak ``sub``. Idempotent: subsequent calls update ``email`` /
    ``full_name`` / ``last_seen_at`` but never change the user ``id``.
    """

    user_repo: UserRepository

    async def execute(
        self,
        *,
        sub: str,
        email: str,
        full_name: str | None,
    ) -> User:
        return await self.user_repo.upsert_from_identity(
            sub=sub,
            email=email,
            full_name=full_name,
        )
