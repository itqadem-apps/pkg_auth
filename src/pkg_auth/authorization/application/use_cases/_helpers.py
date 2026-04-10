"""Internal helpers shared across authorization use cases.

The leading underscore signals "internal" — these are not part of the
public application API and may change between versions.
"""
from __future__ import annotations

from typing import Sequence

from ...domain.exceptions import UnknownPermission
from ...domain.ports import PermissionCatalogRepository
from ...domain.value_objects import PermissionKey


async def validate_permission_keys_exist(
    catalog_repo: PermissionCatalogRepository,
    keys: Sequence[PermissionKey],
) -> None:
    """Raise :class:`UnknownPermission` if any key is not in the catalog.

    Used by :class:`CreateRoleUseCase` and :class:`UpdateRoleUseCase` to
    enforce that role definitions only reference perms that some service
    has actually registered.
    """
    if not keys:
        return
    all_perms = await catalog_repo.list_all()
    known_keys = {str(p.key) for p in all_perms}
    unknown = sorted(str(k) for k in keys if str(k) not in known_keys)
    if unknown:
        raise UnknownPermission(
            f"unknown permission key(s): {unknown}"
        )
