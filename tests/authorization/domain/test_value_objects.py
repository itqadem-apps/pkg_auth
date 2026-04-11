from uuid import uuid4
"""Authorization value object tests."""
from pkg_auth.authorization import (
    OrgId,
    PermissionId,
    RoleId,
    RoleName,
    UserId,
)


def test_user_id_wraps_int():
    uid = UserId(uuid4())
    assert uid.value == 42
    assert int(uid) == 42
    assert str(uid) == "42"


def test_user_id_equality():
    assert UserId(uuid4()) == UserId(uuid4())
    assert UserId(uuid4()) != UserId(uuid4())


def test_user_id_distinct_from_other_id_types():
    # Different types must not compare equal even with the same int value.
    assert UserId(uuid4()) != OrgId(uuid4())
    assert OrgId(uuid4()) != RoleId(uuid4())
    assert RoleId(uuid4()) != PermissionId(uuid4())


def test_id_value_objects_are_hashable():
    s = {UserId(uuid4()), UserId(uuid4()), UserId(uuid4())}
    assert s == {UserId(uuid4()), UserId(uuid4())}


def test_role_name_wraps_string():
    rn = RoleName("admin")
    assert str(rn) == "admin"
    assert rn == RoleName("admin")
    assert rn != RoleName("editor")


def test_role_name_is_hashable():
    s = {RoleName("admin"), RoleName("admin"), RoleName("editor")}
    assert s == {RoleName("admin"), RoleName("editor")}
