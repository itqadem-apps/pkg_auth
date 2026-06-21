"""Internal helpers shared across authorization use cases.

The leading underscore signals "internal" — these are not part of the
public application API and may change between versions.
"""
from __future__ import annotations

from typing import Sequence

from ...domain.exceptions import (
    PermissionVisibilityConflict,
    UnknownPermission,
)
from ...domain.ports import PermissionCatalogRepository
from ...domain.value_objects import PermissionKey, PermissionVisibility


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


async def validate_permission_keys_for_role(
    catalog_repo: PermissionCatalogRepository,
    keys: Sequence[PermissionKey],
    *,
    is_platform_org: bool | None,
) -> None:
    """Validate permission keys for a role, enforcing visibility.

    Always checks existence. When ``is_platform_org`` is not ``None`` (i.e.
    a platform org id is configured and the role is org-scoped), it also
    rejects cross-visibility assignment:

    - a platform-org role may not use ``TENANT_ONLY`` perms;
    - a normal-org role may not use ``PLATFORM_ONLY`` perms.

    Pass ``is_platform_org=None`` for global role templates (org_id is None)
    or when no platform org is configured — only existence is checked, which
    preserves the pre-visibility behavior.
    """
    if not keys:
        return
    all_perms = await catalog_repo.list_all()
    by_key = {str(p.key): p for p in all_perms}
    unknown = sorted(str(k) for k in keys if str(k) not in by_key)
    if unknown:
        raise UnknownPermission(f"unknown permission key(s): {unknown}")

    if is_platform_org is None:
        return

    forbidden = (
        PermissionVisibility.TENANT_ONLY
        if is_platform_org
        else PermissionVisibility.PLATFORM_ONLY
    )
    violators = sorted(
        str(k) for k in keys if by_key[str(k)].visibility == forbidden
    )
    if violators:
        scope = "platform" if is_platform_org else "normal"
        raise PermissionVisibilityConflict(
            f"{forbidden.value} permission(s) {violators} cannot be assigned "
            f"to a role in a {scope} organization"
        )
