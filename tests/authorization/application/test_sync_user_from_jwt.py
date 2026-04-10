"""SyncUserFromJwtUseCase tests."""
from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)

from .fakes import FakeUserRepository


async def test_first_sight_creates_user():
    repo = FakeUserRepository()
    uc = SyncUserFromJwtUseCase(user_repo=repo)
    user = await uc.execute(
        sub="kc-uuid-1", email="alice@example.com", full_name="Alice",
    )
    assert int(user.id) == 1
    assert user.keycloak_sub == "kc-uuid-1"
    assert user.email == "alice@example.com"
    assert user.full_name == "Alice"


async def test_repeat_sight_keeps_id_and_updates_metadata():
    repo = FakeUserRepository()
    uc = SyncUserFromJwtUseCase(user_repo=repo)
    first = await uc.execute(
        sub="kc-uuid-1", email="alice@example.com", full_name="Alice",
    )
    second = await uc.execute(
        sub="kc-uuid-1", email="new@example.com", full_name="Alice Renamed",
    )
    assert int(second.id) == int(first.id)
    assert second.email == "new@example.com"
    assert second.full_name == "Alice Renamed"
    # first_seen_at should be preserved across upserts
    assert second.first_seen_at == first.first_seen_at


async def test_distinct_subs_get_distinct_ids():
    repo = FakeUserRepository()
    uc = SyncUserFromJwtUseCase(user_repo=repo)
    a = await uc.execute(sub="kc-1", email="a@example.com", full_name=None)
    b = await uc.execute(sub="kc-2", email="b@example.com", full_name=None)
    assert int(a.id) != int(b.id)
