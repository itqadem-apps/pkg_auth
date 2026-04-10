"""Authorization value object tests."""
from pkg_auth.authorization import (
    OrgId,
    PermissionId,
    RoleId,
    RoleName,
    UserId,
)


def test_user_id_wraps_int():
    uid = UserId(42)
    assert uid.value == 42
    assert int(uid) == 42
    assert str(uid) == "42"


def test_user_id_equality():
    assert UserId(1) == UserId(1)
    assert UserId(1) != UserId(2)


def test_user_id_distinct_from_other_id_types():
    # Different types must not compare equal even with the same int value.
    assert UserId(1) != OrgId(1)
    assert OrgId(1) != RoleId(1)
    assert RoleId(1) != PermissionId(1)


def test_id_value_objects_are_hashable():
    s = {UserId(1), UserId(1), UserId(2)}
    assert s == {UserId(1), UserId(2)}


def test_role_name_wraps_string():
    rn = RoleName("admin")
    assert str(rn) == "admin"
    assert rn == RoleName("admin")
    assert rn != RoleName("editor")


def test_role_name_is_hashable():
    s = {RoleName("admin"), RoleName("admin"), RoleName("editor")}
    assert s == {RoleName("admin"), RoleName("editor")}
