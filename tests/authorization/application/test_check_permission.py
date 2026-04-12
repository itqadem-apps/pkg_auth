"""CheckPermissionUseCase tests."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    AuthContext,
    MissingPermission,
    OrgId,
    UserId,
)
from pkg_auth.authorization.application.use_cases.check_permission import (
    CheckPermissionUseCase,
)


def _ctx(*perms: str, role: str = "editor") -> AuthContext:
    return AuthContext(
        user_id=UserId(uuid4()),
        organization_id=OrgId(uuid4()),
        role_names=frozenset({role}),
        perms=frozenset(perms),
    )


async def test_silent_when_perm_granted():
    ctx = _ctx("course:edit")
    uc = CheckPermissionUseCase()
    await uc.execute(ctx, "course:edit")  # should not raise


async def test_raises_when_perm_missing():
    ctx = _ctx("course:view", role="viewer")
    uc = CheckPermissionUseCase()
    with pytest.raises(MissingPermission, match="course:edit"):
        await uc.execute(ctx, "course:edit")
