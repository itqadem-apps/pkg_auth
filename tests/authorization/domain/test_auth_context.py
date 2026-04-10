"""AuthContext.has() / .require() behavior."""
import pytest

from pkg_auth.authorization import (
    AuthContext,
    MissingPermission,
    OrgId,
    RoleName,
    UserId,
)


def _make_ctx(*perms: str) -> AuthContext:
    return AuthContext(
        user_id=UserId(1),
        organization_id=OrgId(2),
        role_name=RoleName("editor"),
        perms=frozenset(perms),
    )


def test_has_returns_true_for_granted_perm():
    ctx = _make_ctx("course:edit", "course:view")
    assert ctx.has("course:edit") is True
    assert ctx.has("course:view") is True


def test_has_returns_false_for_missing_perm():
    ctx = _make_ctx("course:view")
    assert ctx.has("course:edit") is False


def test_has_returns_false_for_empty_perms():
    ctx = _make_ctx()
    assert ctx.has("anything:at_all") is False


def test_require_silent_when_granted():
    ctx = _make_ctx("course:edit")
    # Should not raise.
    ctx.require("course:edit")


def test_require_raises_when_missing():
    ctx = _make_ctx("course:view")
    with pytest.raises(MissingPermission, match="course:edit"):
        ctx.require("course:edit")


def test_require_error_message_includes_org_and_role():
    ctx = AuthContext(
        user_id=UserId(7),
        organization_id=OrgId(99),
        role_name=RoleName("viewer"),
        perms=frozenset(),
    )
    with pytest.raises(MissingPermission) as exc_info:
        ctx.require("course:edit")
    msg = str(exc_info.value)
    assert "course:edit" in msg
    assert "99" in msg          # org id
    assert "viewer" in msg      # role name


def test_auth_context_is_frozen():
    ctx = _make_ctx("course:edit")
    with pytest.raises(Exception):
        ctx.perms = frozenset()  # type: ignore[misc]
