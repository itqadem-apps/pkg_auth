"""Authorization exception hierarchy."""
from pkg_auth.authorization import (
    AuthorizationError,
    MissingPermission,
    NotAMember,
    UnknownOrganization,
    UnknownRole,
    UnknownUser,
    UserNotProvisioned,
)


def test_all_inherit_from_authorization_error():
    assert issubclass(NotAMember, AuthorizationError)
    assert issubclass(MissingPermission, AuthorizationError)
    assert issubclass(UnknownOrganization, AuthorizationError)
    assert issubclass(UnknownUser, AuthorizationError)
    assert issubclass(UnknownRole, AuthorizationError)
    assert issubclass(UserNotProvisioned, AuthorizationError)


def test_authorization_error_is_a_plain_exception():
    assert issubclass(AuthorizationError, Exception)


def test_authorization_error_does_not_inherit_from_authentication_error():
    # Authentication and authorization errors are separate hierarchies so
    # integration layers can map them to different HTTP statuses.
    from pkg_auth.authentication import AuthenticationError

    assert not issubclass(AuthorizationError, AuthenticationError)
    assert not issubclass(AuthenticationError, AuthorizationError)


def test_can_catch_specific_via_base():
    try:
        raise MissingPermission("course:edit required")
    except AuthorizationError as exc:
        assert "course:edit" in str(exc)
