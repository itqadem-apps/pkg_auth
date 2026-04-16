"""ResolveUserFromJwtUseCase tests (Mode B reader-only path)."""
import pytest

from pkg_auth.authorization import UserNotProvisioned
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)

from .fakes import FakeUserRepository


async def test_returns_existing_user():
    repo = FakeUserRepository()
    seeded = await repo.upsert_from_identity(
        sub="kc-uuid-1", email="alice@example.com", full_name="Alice",
    )
    uc = ResolveUserFromJwtUseCase(user_repo=repo)

    resolved = await uc.execute(sub="kc-uuid-1")

    assert resolved.id == seeded.id
    assert resolved.email == "alice@example.com"


async def test_raises_when_user_not_provisioned():
    repo = FakeUserRepository()
    uc = ResolveUserFromJwtUseCase(user_repo=repo)

    with pytest.raises(UserNotProvisioned) as exc_info:
        await uc.execute(sub="kc-unknown")

    assert "kc-unknown" in str(exc_info.value)


async def test_does_not_write_on_miss():
    repo = FakeUserRepository()
    uc = ResolveUserFromJwtUseCase(user_repo=repo)

    with pytest.raises(UserNotProvisioned):
        await uc.execute(sub="kc-unknown")

    # Repo must stay empty — Mode B readers never insert.
    assert await repo.get_by_keycloak_sub("kc-unknown") is None
