"""Authorization value object tests."""
from uuid import UUID, uuid4

from pkg_auth.authorization import (
    OrgId,
    PermissionId,
    RoleId,
    RoleName,
    UserId,
)


def test_user_id_wraps_uuid():
    raw = uuid4()
    uid = UserId(raw)
    assert uid.value == raw
    assert isinstance(uid.value, UUID)
    assert str(uid) == str(raw)


def test_user_id_equality():
    raw = uuid4()
    assert UserId(raw) == UserId(raw)
    assert UserId(uuid4()) != UserId(uuid4())


def test_user_id_distinct_from_other_id_types():
    raw = uuid4()
    # Different wrapper types must not compare equal even with the same UUID.
    assert UserId(raw) != OrgId(raw)
    assert OrgId(raw) != RoleId(raw)
    assert RoleId(raw) != PermissionId(raw)


def test_id_value_objects_are_hashable():
    a, b = uuid4(), uuid4()
    s = {UserId(a), UserId(a), UserId(b)}
    assert s == {UserId(a), UserId(b)}


def test_role_name_wraps_string():
    rn = RoleName("admin")
    assert str(rn) == "admin"
    assert rn == RoleName("admin")
    assert rn != RoleName("editor")


def test_role_name_is_hashable():
    s = {RoleName("admin"), RoleName("admin"), RoleName("editor")}
    assert s == {RoleName("admin"), RoleName("editor")}
