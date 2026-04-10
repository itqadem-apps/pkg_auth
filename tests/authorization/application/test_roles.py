"""Role use case tests (create / update / delete + perm validation)."""
import pytest

from pkg_auth.authorization import (
    OrgId,
    PermissionKey,
    RoleId,
    RoleName,
    UnknownOrganization,
    UnknownPermission,
    UnknownRole,
)
from pkg_auth.authorization.application.use_cases.create_role import (
    CreateRoleUseCase,
)
from pkg_auth.authorization.application.use_cases.delete_role import (
    DeleteRoleUseCase,
)
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)
from pkg_auth.authorization.application.use_cases.update_role import (
    UpdateRoleUseCase,
)

from .fakes import (
    FakeOrganizationRepository,
    FakePermissionCatalogRepository,
    FakeRoleRepository,
)


async def _seed_catalog(repo: FakePermissionCatalogRepository) -> None:
    register = RegisterPermissionCatalogUseCase(catalog_repo=repo)
    await register.execute(
        service_name="courses",
        entries=[
            (PermissionKey("course:edit"), None),
            (PermissionKey("course:view"), None),
            (PermissionKey("course:delete"), None),
        ],
    )


async def test_create_role_with_known_perms():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)
    org = await org_repo.create(slug="acme", name="ACME")

    uc = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    role = await uc.execute(
        org_id=org.id,
        name=RoleName("editor"),
        description="course editor",
        permission_keys=[PermissionKey("course:edit"), PermissionKey("course:view")],
    )
    assert str(role.name) == "editor"
    assert role.description == "course editor"
    assert role.permission_keys == frozenset({"course:edit", "course:view"})


async def test_create_role_with_unknown_org_raises():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    uc = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    with pytest.raises(UnknownOrganization):
        await uc.execute(
            org_id=OrgId(999),
            name=RoleName("editor"),
            description=None,
            permission_keys=[],
        )


async def test_create_role_with_unknown_perm_raises():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)
    org = await org_repo.create(slug="acme", name="ACME")

    uc = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    with pytest.raises(UnknownPermission, match="not-a-real:perm"):
        await uc.execute(
            org_id=org.id,
            name=RoleName("editor"),
            description=None,
            permission_keys=[
                PermissionKey("course:edit"),
                PermissionKey("not-a-real:perm"),
            ],
        )


async def test_create_global_role_template_no_org():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)

    uc = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    role = await uc.execute(
        org_id=None,
        name=RoleName("global-viewer"),
        description="reusable",
        permission_keys=[PermissionKey("course:view")],
    )
    assert role.organization_id is None


async def test_update_role_changes_perms():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)
    org = await org_repo.create(slug="acme", name="ACME")
    create = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    role = await create.execute(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )

    update = UpdateRoleUseCase(role_repo=role_repo, catalog_repo=catalog)
    updated = await update.execute(
        role.id,
        permission_keys=[
            PermissionKey("course:edit"),
            PermissionKey("course:view"),
        ],
    )
    assert updated.permission_keys == frozenset({"course:edit", "course:view"})


async def test_update_role_unknown_role_raises():
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    uc = UpdateRoleUseCase(role_repo=role_repo, catalog_repo=catalog)
    with pytest.raises(UnknownRole):
        await uc.execute(RoleId(999), name=RoleName("nope"))


async def test_update_role_unknown_perm_raises():
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)
    org = await org_repo.create(slug="acme", name="ACME")
    create = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    role = await create.execute(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )

    update = UpdateRoleUseCase(role_repo=role_repo, catalog_repo=catalog)
    with pytest.raises(UnknownPermission, match="not-a-real:perm"):
        await update.execute(
            role.id,
            permission_keys=[PermissionKey("not-a-real:perm")],
        )


async def test_delete_role_idempotent():
    role_repo = FakeRoleRepository()
    catalog = FakePermissionCatalogRepository()
    await _seed_catalog(catalog)
    org_repo = FakeOrganizationRepository()
    org = await org_repo.create(slug="acme", name="ACME")
    create = CreateRoleUseCase(
        organization_repo=org_repo, role_repo=role_repo, catalog_repo=catalog,
    )
    role = await create.execute(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[],
    )

    delete = DeleteRoleUseCase(role_repo=role_repo)
    await delete.execute(role.id)
    await delete.execute(role.id)  # second call: no error
    assert await role_repo.get(role.id) is None
