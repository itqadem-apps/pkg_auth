"""Authorization (ACL) exceptions.

These are deliberately a *separate* hierarchy from
``pkg_auth.authentication.domain.exceptions``: authentication failures
are 401, authorization failures are 403/404. Integration layers map
each to the right HTTP status.
"""
from __future__ import annotations


class AuthorizationError(Exception):
    """Base for all authorization (ACL) failures."""


class NotAMember(AuthorizationError):
    """The user has no membership in the requested organization."""


class MissingPermission(AuthorizationError):
    """The user's role in the organization does not include the required permission."""


class UnknownOrganization(AuthorizationError):
    """The referenced organization does not exist."""


class UnknownUser(AuthorizationError):
    """The referenced user does not exist."""


class UnknownRole(AuthorizationError):
    """The referenced role does not exist."""


class UnknownPermission(AuthorizationError):
    """A referenced permission key is not registered in the catalog."""
