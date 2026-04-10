"""Register a service's permission catalog at startup."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ...domain.ports import PermissionCatalogRepository
from ...domain.value_objects import PermissionKey


@dataclass(slots=True)
class RegisterPermissionCatalogUseCase:
    """Idempotently register the permission keys a service knows about.

    Each consuming service calls this on boot with its static perm
    list. The repository upserts by ``(service_name, key)`` so calling
    it on every restart is safe and converges.

    The users service reads from the resulting ``acl.permissions`` table
    when building role-editor UIs.
    """

    catalog_repo: PermissionCatalogRepository

    async def execute(
        self,
        *,
        service_name: str,
        entries: Sequence[tuple[PermissionKey, str | None]],
    ) -> None:
        await self.catalog_repo.register_many(
            service_name=service_name,
            entries=entries,
        )
