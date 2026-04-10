"""ResolveAuthContextUseCase tests."""
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
    role_repo = FakeRoleRepository()
    role = await role_repo.create(
        org_id=OrgId(1),
        name=RoleName("editor"),
        description=None,
        permission_keys=[
            PermissionKey("course:edit"),
            PermissionKey("course:view"),
        ],
    )
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    await membership_repo.upsert(
        user_id=UserId(1),
        org_id=OrgId(1),
        role_id=role.id,
        status="active",
    )

    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    ctx = await uc.execute(UserId(1), OrgId(1))

    assert ctx.user_id == UserId(1)
    assert ctx.organization_id == OrgId(1)
    assert str(ctx.role_name) == "editor"
    assert ctx.has("course:edit")
    assert ctx.has("course:view")
    assert not ctx.has("course:delete")


async def test_resolve_raises_not_a_member_when_no_membership():
    role_repo = FakeRoleRepository()
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    with pytest.raises(NotAMember):
        await uc.execute(UserId(1), OrgId(1))


async def test_resolve_raises_not_a_member_for_suspended_membership():
    role_repo = FakeRoleRepository()
    role = await role_repo.create(
        org_id=OrgId(1),
        name=RoleName("viewer"),
        description=None,
        permission_keys=[],
    )
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    await membership_repo.upsert(
        user_id=UserId(1),
        org_id=OrgId(1),
        role_id=role.id,
        status="suspended",
    )
    uc = ResolveAuthContextUseCase(membership_repo=membership_repo)
    with pytest.raises(NotAMember):
        await uc.execute(UserId(1), OrgId(1))
