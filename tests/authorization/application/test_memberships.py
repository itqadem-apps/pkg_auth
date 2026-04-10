"""Membership use case tests (upsert / delete)."""
import pytest

from pkg_auth.authorization import (
    OrgId,
    PermissionKey,
    RoleId,
    RoleName,
    UnknownOrganization,
    UnknownRole,
    UnknownUser,
    UserId,
)
from pkg_auth.authorization.application.use_cases.delete_membership import (
    DeleteMembershipUseCase,
)
from pkg_auth.authorization.application.use_cases.upsert_membership import (
    UpsertMembershipUseCase,
)

from .fakes import (
    FakeMembershipRepository,
    FakeOrganizationRepository,
    FakeRoleRepository,
    FakeUserRepository,
)


async def _setup():
    user_repo = FakeUserRepository()
    org_repo = FakeOrganizationRepository()
    role_repo = FakeRoleRepository()
    membership_repo = FakeMembershipRepository(role_repo=role_repo)
    user = await user_repo.upsert_from_identity(
        sub="kc-1", email="alice@example.com", full_name="Alice",
    )
    org = await org_repo.create(slug="acme", name="ACME")
    role = await role_repo.create(
        org_id=org.id,
        name=RoleName("editor"),
        description=None,
        permission_keys=[PermissionKey("course:edit")],
    )
    return user_repo, org_repo, role_repo, membership_repo, user, org, role


async def test_upsert_creates_membership():
    user_repo, org_repo, role_repo, m_repo, user, org, role = await _setup()
    uc = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    membership = await uc.execute(
        user_id=user.id, org_id=org.id, role_id=role.id,
    )
    assert membership.user_id == user.id
    assert membership.organization_id == org.id
    assert membership.role_id == role.id
    assert membership.status == "active"
    assert str(membership.role_name) == "editor"


async def test_upsert_idempotent():
    user_repo, org_repo, role_repo, m_repo, user, org, role = await _setup()
    uc = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    first = await uc.execute(user_id=user.id, org_id=org.id, role_id=role.id)
    second = await uc.execute(user_id=user.id, org_id=org.id, role_id=role.id)
    assert first.id == second.id
    # second call should keep joined_at stable
    assert first.joined_at == second.joined_at


async def test_upsert_unknown_user_raises():
    user_repo, org_repo, role_repo, m_repo, _, org, role = await _setup()
    uc = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    with pytest.raises(UnknownUser):
        await uc.execute(user_id=UserId(999), org_id=org.id, role_id=role.id)


async def test_upsert_unknown_org_raises():
    user_repo, org_repo, role_repo, m_repo, user, _, role = await _setup()
    uc = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    with pytest.raises(UnknownOrganization):
        await uc.execute(user_id=user.id, org_id=OrgId(999), role_id=role.id)


async def test_upsert_unknown_role_raises():
    user_repo, org_repo, role_repo, m_repo, user, org, _ = await _setup()
    uc = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    with pytest.raises(UnknownRole):
        await uc.execute(user_id=user.id, org_id=org.id, role_id=RoleId(999))


async def test_delete_is_idempotent():
    user_repo, org_repo, role_repo, m_repo, user, org, role = await _setup()
    upsert = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=org_repo,
        role_repo=role_repo,
        membership_repo=m_repo,
    )
    await upsert.execute(user_id=user.id, org_id=org.id, role_id=role.id)

    delete = DeleteMembershipUseCase(membership_repo=m_repo)
    await delete.execute(user_id=user.id, org_id=org.id)
    await delete.execute(user_id=user.id, org_id=org.id)  # second call: no error
    assert await m_repo.get(user.id, org.id) is None
