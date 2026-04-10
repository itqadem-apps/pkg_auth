"""PermissionKey format validation."""
import pytest

from pkg_auth.authorization import PermissionKey


@pytest.mark.parametrize(
    "valid_key",
    [
        "course:edit",
        "course:view",
        "media-library:upload",
        "billing:invoice:refund",
        "user_settings:read",
        "a:b",
        "abc:def_xyz",
        "x1:y2",
    ],
)
def test_valid_permission_keys(valid_key):
    key = PermissionKey(valid_key)
    assert str(key) == valid_key


@pytest.mark.parametrize(
    "invalid_key",
    [
        "",
        "admin",                # no colon
        ":missing-resource",    # leading colon
        "missing-action:",      # trailing colon
        "Course:edit",          # uppercase resource
        "course :edit",         # space in segment
        "course:Edit",          # uppercase action
        "1course:edit",         # leading digit
        "course::edit",         # empty middle segment
        "course:",              # missing action
        "_course:edit",         # leading underscore
    ],
)
def test_invalid_permission_keys(invalid_key):
    with pytest.raises(ValueError, match="Invalid permission key"):
        PermissionKey(invalid_key)


def test_permission_key_is_frozen():
    key = PermissionKey("course:edit")
    with pytest.raises(Exception):
        key.value = "course:view"  # type: ignore[misc]
