"""ResolveAuthContextUseCase service-guard tests."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    CatalogEntry,
    NotAMember,
    OrgId,
    PermissionKey,
    RoleName,
    ServiceName,
    UserId,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

from .fakes import (
    FakeMembershipRepository,
    FakeOrganizationServiceRepository,
    FakePermissionCatalogRepository,
    FakeRoleRepository,
)


async def _setup(*, enabled_services):
    user_id = UserId(uuid4())
    org_id = OrgId(uuid4())

    catalog = FakePermissionCatalogRepository()
    await catalog.register_many(
        service_name="courses",
        entries=[CatalogEntry(PermissionKey("course:edit"), "Edit course")],
    )
    await catalog.register_many(
        service_name="users",
        entries=[CatalogEntry(PermissionKey("users:read"), "Read user")],
    )

    roles = FakeRoleRepository()
    role = await roles.create(
        org_id=org_id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit"), PermissionKey("users:read")],
    )
    memberships = FakeMembershipRepository(role_repo=roles)
    await memberships.upsert(
        user_id=user_id, org_id=org_id, role_id=role.id, status="active"
    )

    org_services = FakeOrganizationServiceRepository()
    for svc in enabled_services:
        await org_services.enable(org_id, ServiceName(svc), source="manual")

    return user_id, org_id, catalog, memberships, org_services


async def test_guard_drops_perms_for_disabled_services():
    user_id, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=["users"]  # courses NOT enabled
    )
    uc = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services,
        catalog_repo=catalog,
    )
    ctx = await uc.execute(user_id, org_id)
    assert ctx.perms == frozenset({"users:read"})  # course:edit dropped


async def test_guard_keeps_perms_for_enabled_services():
    user_id, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=["users", "courses"]
    )
    uc = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services,
        catalog_repo=catalog,
    )
    ctx = await uc.execute(user_id, org_id)
    assert ctx.perms == frozenset({"users:read", "course:edit"})


async def test_default_deny_drops_everything_when_nothing_enabled():
    user_id, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=[]
    )
    uc = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services,
        catalog_repo=catalog,
    )
    ctx = await uc.execute(user_id, org_id)
    assert ctx.perms == frozenset()


async def test_platform_org_bypasses_guard():
    user_id, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=[]  # nothing enabled, but platform org bypasses
    )
    uc = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services,
        catalog_repo=catalog,
        platform_org_id=org_id,
    )
    ctx = await uc.execute(user_id, org_id)
    assert ctx.perms == frozenset({"users:read", "course:edit"})


async def test_guard_unwired_means_no_filtering():
    user_id, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=[]
    )
    uc = ResolveAuthContextUseCase(membership_repo=memberships)
    ctx = await uc.execute(user_id, org_id)
    assert ctx.perms == frozenset({"users:read", "course:edit"})


async def test_not_a_member_raises():
    _, org_id, catalog, memberships, org_services = await _setup(
        enabled_services=["users"]
    )
    uc = ResolveAuthContextUseCase(
        membership_repo=memberships,
        org_service_repo=org_services,
        catalog_repo=catalog,
    )
    with pytest.raises(NotAMember):
        await uc.execute(UserId(uuid4()), org_id)
