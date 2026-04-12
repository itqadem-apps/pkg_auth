"""Organization use case tests (create / update / delete / list_for_user)."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import OrgId, UnknownOrganization, UserId
from pkg_auth.authorization.application.use_cases.create_organization import (
    CreateOrganizationUseCase,
)
from pkg_auth.authorization.application.use_cases.delete_organization import (
    DeleteOrganizationUseCase,
)
from pkg_auth.authorization.application.use_cases.list_user_organizations import (
    ListUserOrganizationsUseCase,
)
from pkg_auth.authorization.application.use_cases.update_organization import (
    UpdateOrganizationUseCase,
)

from .fakes import FakeOrganizationRepository


async def test_create_persists_organization():
    repo = FakeOrganizationRepository()
    uc = CreateOrganizationUseCase(organization_repo=repo)
    org = await uc.execute(slug="acme", name="ACME Corp")
    assert org.slug == "acme"
    assert org.name == "ACME Corp"
    # Round-trips through the repo
    fetched = await repo.get(org.id)
    assert fetched is not None
    assert fetched.id == org.id


async def test_update_changes_name_only():
    repo = FakeOrganizationRepository()
    org = await repo.create(slug="acme", name="ACME Corp")
    uc = UpdateOrganizationUseCase(organization_repo=repo)
    updated = await uc.execute(org.id, name="ACME Inc")
    assert updated.name == "ACME Inc"
    assert updated.slug == "acme"  # slug is immutable


async def test_update_unknown_org_raises():
    repo = FakeOrganizationRepository()
    uc = UpdateOrganizationUseCase(organization_repo=repo)
    with pytest.raises(UnknownOrganization):
        await uc.execute(OrgId(uuid4()), name="Nope")


async def test_delete_is_idempotent():
    repo = FakeOrganizationRepository()
    org = await repo.create(slug="acme", name="ACME")
    uc = DeleteOrganizationUseCase(organization_repo=repo)
    await uc.execute(org.id)
    await uc.execute(org.id)  # should not raise
    assert await repo.get(org.id) is None


async def test_list_for_user_returns_linked_orgs():
    repo = FakeOrganizationRepository()
    user = UserId(uuid4())
    a = await repo.create(slug="acme", name="ACME")
    b = await repo.create(slug="globex", name="Globex")
    repo._link(user, a.id)
    repo._link(user, b.id)

    uc = ListUserOrganizationsUseCase(organization_repo=repo)
    orgs = await uc.execute(user)
    assert {o.slug for o in orgs} == {"acme", "globex"}


async def test_list_for_user_returns_empty_when_no_memberships():
    repo = FakeOrganizationRepository()
    await repo.create(slug="acme", name="ACME")
    uc = ListUserOrganizationsUseCase(organization_repo=repo)
    orgs = await uc.execute(UserId(uuid4()))
    assert orgs == []
