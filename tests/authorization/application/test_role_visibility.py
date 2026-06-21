"""Permission-visibility enforcement in create/update role use cases."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    CatalogEntry,
    PermissionKey,
    PermissionVisibility,
    PermissionVisibilityConflict,
    RoleName,
)
from pkg_auth.authorization.application.use_cases.create_role import (
    CreateRoleUseCase,
)
from pkg_auth.authorization.application.use_cases.update_role import (
    UpdateRoleUseCase,
)

from .fakes import (
    FakeOrganizationRepository,
    FakePermissionCatalogRepository,
    FakeRoleRepository,
)

PLATFORM = PermissionVisibility.PLATFORM_ONLY
TENANT = PermissionVisibility.TENANT_ONLY


async def _seed():
    catalog = FakePermissionCatalogRepository()
    await catalog.register_many(
        service_name="users",
        entries=[
            CatalogEntry(PermissionKey("organizations:create"), None, PLATFORM),
            CatalogEntry(PermissionKey("course:edit"), None),  # shared
            CatalogEntry(PermissionKey("wellbeing:survey"), None, TENANT),
        ],
    )
    org_repo = FakeOrganizationRepository()
    platform = await org_repo.create(slug="platform", name="Platform")
    normal = await org_repo.create(slug="acme", name="ACME")
    return catalog, org_repo, platform, normal


async def test_normal_org_role_cannot_use_platform_only_perm():
    catalog, org_repo, platform, normal = await _seed()
    uc = CreateRoleUseCase(
        organization_repo=org_repo,
        role_repo=FakeRoleRepository(),
        catalog_repo=catalog,
        platform_org_id=platform.id,
    )
    with pytest.raises(PermissionVisibilityConflict):
        await uc.execute(
            org_id=normal.id,
            name=RoleName("admin"),
            description=None,
            permission_keys=[PermissionKey("organizations:create")],
        )


async def test_platform_org_role_cannot_use_tenant_only_perm():
    catalog, org_repo, platform, normal = await _seed()
    uc = CreateRoleUseCase(
        organization_repo=org_repo,
        role_repo=FakeRoleRepository(),
        catalog_repo=catalog,
        platform_org_id=platform.id,
    )
    with pytest.raises(PermissionVisibilityConflict):
        await uc.execute(
            org_id=platform.id,
            name=RoleName("admin"),
            description=None,
            permission_keys=[PermissionKey("wellbeing:survey")],
        )


async def test_shared_perm_allowed_everywhere():
    catalog, org_repo, platform, normal = await _seed()
    uc = CreateRoleUseCase(
        organization_repo=org_repo,
        role_repo=FakeRoleRepository(),
        catalog_repo=catalog,
        platform_org_id=platform.id,
    )
    role = await uc.execute(
        org_id=normal.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )
    assert role.permission_keys == frozenset({"course:edit"})


async def test_no_platform_org_configured_skips_visibility_check():
    catalog, org_repo, platform, normal = await _seed()
    uc = CreateRoleUseCase(
        organization_repo=org_repo,
        role_repo=FakeRoleRepository(),
        catalog_repo=catalog,
        # platform_org_id not set
    )
    role = await uc.execute(
        org_id=normal.id,
        name=RoleName("admin"),
        description=None,
        permission_keys=[PermissionKey("organizations:create")],
    )
    assert "organizations:create" in role.permission_keys


async def test_update_role_enforces_visibility():
    catalog, org_repo, platform, normal = await _seed()
    role_repo = FakeRoleRepository()
    role = await role_repo.create(
        org_id=normal.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )
    uc = UpdateRoleUseCase(
        role_repo=role_repo,
        catalog_repo=catalog,
        platform_org_id=platform.id,
    )
    with pytest.raises(PermissionVisibilityConflict):
        await uc.execute(
            role.id,
            permission_keys=[PermissionKey("organizations:create")],
        )
