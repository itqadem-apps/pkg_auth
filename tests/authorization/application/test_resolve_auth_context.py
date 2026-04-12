"""ResolveAuthContextUseCase tests."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    NotAMember,
    OrgId,
    PermissionKey,
    RoleName,
    UserId,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)

from .fakes import FakeMembershipRepository, FakeRoleRepository


async def test_resolve_returns_auth_context_for_active_member():
    user_id = UserId(uuid4())
    org_id = OrgId(uuid4())
    role_repo = FakeRoleRepository()
    role = await role_repo.create(
        org_id=org_id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[
            PermissionKey("course:edit"),
            PermissionKey("course:view"),
        ],
    )
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    await membership_repo.upsert(
        user_id=user_id,
        org_id=org_id,
        role_id=role.id,
        status="active",
    )

    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    ctx = await uc.execute(user_id, org_id)

    assert ctx.user_id == user_id
    assert ctx.organization_id == org_id
    assert "editor" in ctx.role_names
    assert ctx.has("course:edit")
    assert ctx.has("course:view")
    assert not ctx.has("course:delete")


async def test_resolve_merges_perms_across_multiple_roles_in_same_org():
    user_id = UserId(uuid4())
    org_id = OrgId(uuid4())
    role_repo = FakeRoleRepository()
    editor = await role_repo.create(
        org_id=org_id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )
    approver = await role_repo.create(
        org_id=org_id,
        name=RoleName("approver"),
        description=None,
        permission_keys=[PermissionKey("course:approve")],
    )
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    await membership_repo.upsert(
        user_id=user_id, org_id=org_id, role_id=editor.id, status="active",
    )
    await membership_repo.upsert(
        user_id=user_id, org_id=org_id, role_id=approver.id, status="active",
    )

    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    ctx = await uc.execute(user_id, org_id)

    assert ctx.role_names == frozenset({"editor", "approver"})
    assert ctx.has("course:edit")
    assert ctx.has("course:approve")


async def test_resolve_raises_not_a_member_when_no_membership():
    role_repo = FakeRoleRepository()
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    with pytest.raises(NotAMember):
        await uc.execute(UserId(uuid4()), OrgId(uuid4()))


async def test_resolve_raises_not_a_member_for_suspended_membership():
    user_id = UserId(uuid4())
    org_id = OrgId(uuid4())
    role_repo = FakeRoleRepository()
    role = await role_repo.create(
        org_id=org_id,
        name=RoleName("viewer"),
        description=None,
        permission_keys=[],
    )
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    await membership_repo.upsert(
        user_id=user_id,
        org_id=org_id,
        role_id=role.id,
        status="suspended",
    )
    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    with pytest.raises(NotAMember):
        await uc.execute(user_id, org_id)
