"""CheckPermissionUseCase tests."""
import pytest

from pkg_auth.authorization import (
    AuthContext,
    MissingPermission,
    OrgId,
    RoleName,
    UserId,
)
from pkg_auth.authorization.application.use_cases.check_permission import (
    CheckPermissionUseCase,
)


async def test_silent_when_perm_granted():
    ctx = AuthContext(
        user_id=UserId(1),
        organization_id=OrgId(1),
        role_name=RoleName("editor"),
        perms=frozenset({"course:edit"}),
    )
    uc = CheckPermissionUseCase()
    await uc.execute(ctx, "course:edit")  # should not raise


async def test_raises_when_perm_missing():
    ctx = AuthContext(
        user_id=UserId(1),
        organization_id=OrgId(1),
        role_name=RoleName("viewer"),
        perms=frozenset({"course:view"}),
    )
    uc = CheckPermissionUseCase()
    with pytest.raises(MissingPermission, match="course:edit"):
        await uc.execute(ctx, "course:edit")
