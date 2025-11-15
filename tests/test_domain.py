# tests/test_domain.py
import pytest

from src.pkg_auth.domain.constants import ClaimSet
from src.pkg_auth.domain.entities import AccessRights, AccessContext, IdentityInfo, SessionInfo
from src.pkg_auth.domain.value_objects import EmailAddress, AccessRequirement, require_permissions, require_realm_roles, \
    require_client_roles, Subject, RealmName


def test_email_value_object():
    email = EmailAddress("test@example.com")
    assert str(email) == "test@example.com"

    with pytest.raises(ValueError):
        EmailAddress("invalid-email")


def test_access_requirement():
    ar = AccessRequirement(ClaimSet.PERMISSION, any_of=["a", "b"])
    assert ar.claim_set == ClaimSet.PERMISSION
    assert ar.any_of == ("a", "b")
    assert ar.all_of == ()

    ar = AccessRequirement(ClaimSet.REALM_ROLE, all_of=["c", "d"])
    assert ar.claim_set == ClaimSet.REALM_ROLE
    assert ar.any_of == ()
    assert ar.all_of == ("c", "d")

    ar = AccessRequirement(ClaimSet.CLIENT_ROLE, any_of="e", all_of="f")
    assert ar.claim_set == ClaimSet.CLIENT_ROLE
    assert ar.any_of == ("e",)
    assert ar.all_of == ("f",)


def test_require_helpers():
    assert require_permissions("a", "b") == AccessRequirement(
        ClaimSet.PERMISSION, any_of=("a", "b")
    )
    assert require_permissions("a", "b", any_of=False) == AccessRequirement(
        ClaimSet.PERMISSION, all_of=("a", "b")
    )
    assert require_realm_roles("c") == AccessRequirement(
        ClaimSet.REALM_ROLE, any_of=("c",)
    )
    assert require_client_roles("d", "e", any_of=False) == AccessRequirement(
        ClaimSet.CLIENT_ROLE, all_of=("d", "e")
    )


def test_access_rights():
    rights = AccessRights(
        realm_roles={"a", "b"},
        client_roles={"c", "d"},
        permissions={"e", "f"},
        scopes={"g", "h"},
        audiences={"i", "j"},
    )

    # --- contains ---
    assert rights.contains("a", ClaimSet.REALM_ROLE)
    assert not rights.contains("z", ClaimSet.REALM_ROLE)

    # --- contains_any ---
    assert rights.contains_any(["a", "z"], ClaimSet.REALM_ROLE)
    assert not rights.contains_any(["y", "z"], ClaimSet.CLIENT_ROLE)

    # --- contains_all ---
    assert rights.contains_all(["c", "d"], ClaimSet.CLIENT_ROLE)
    assert not rights.contains_all(["c", "z"], ClaimSet.CLIENT_ROLE)

    # --- test all claim sets ---
    assert rights.contains_any(["e", "y"], ClaimSet.PERMISSION)
    assert rights.contains_all(["g", "h"], ClaimSet.SCOPE)
    assert not rights.contains_all(["i", "z"], ClaimSet.AUDIENCE)


def test_access_context():
    identity = IdentityInfo(
        subject=Subject("sub"),
        email=EmailAddress("test@example.com"),
        full_name="Test User",
        preferred_username="testuser",
    )
    session = SessionInfo(
        session_id="sid",
        realm=RealmName("test-realm"),
    )
    ctx = AccessContext(identity=identity, session=session)

    assert ctx.subject == "sub"
    assert ctx.email == "test@example.com"
    assert ctx.full_name == "Test User"
    assert ctx.preferred_username == "testuser"
    assert ctx.session_id == "sid"
    assert ctx.realm == "test-realm"
