# src/pkg_auth/domain/value_objects.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from .constants import ClaimSet


# --- Identity value objects ----------------------------------------------


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """
    Simple email value object.

    You can keep validation light here on purpose to avoid being too strict.
    """
    value: str

    def __post_init__(self) -> None:
        if "@" not in self.value:
            raise ValueError(f"Invalid email address: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Subject:
    """
    Represents the IdP subject (Keycloak `sub` claim).

    Kept as a separate type so you don't accidentally treat it as your
    internal user ID.
    """
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RealmName:
    """
    Represents a Keycloak realm name, extracted from the issuer URL.
    """
    value: str

    def __str__(self) -> str:
        return self.value


# --- Access / claims value objects ---------------------------------------


def _normalize(values: Iterable[str]) -> Tuple[str, ...]:
    """
    Normalize an iterable of strings into a tuple.
    If a plain string is passed, treat it as a single-element collection.
    """
    if isinstance(values, str):
        return (values,)
    return tuple(values)


@dataclass(frozen=True, slots=True)
class AccessRequirement:
    """
    Declarative description of an authorization requirement.

    - claim_set: which set we are checking (permissions, realm roles, scopes, etc.)
    - any_of:   at least one of these must be present (OR)
    - all_of:   all of these must be present (AND)

    You can use both any_of and all_of together if needed.
    """

    claim_set: ClaimSet
    any_of: Tuple[str, ...] = ()
    all_of: Tuple[str, ...] = ()

    def __init__(
            self,
            claim_set: ClaimSet,
            any_of: Iterable[str] | None = None,
            all_of: Iterable[str] | None = None,
    ) -> None:
        object.__setattr__(self, "claim_set", claim_set)
        object.__setattr__(self, "any_of", _normalize(any_of or ()))
        object.__setattr__(self, "all_of", _normalize(all_of or ()))


def require_permissions(*perms: str, any_of: bool = True) -> AccessRequirement:
    if any_of:
        return AccessRequirement(ClaimSet.PERMISSION, any_of=perms)
    return AccessRequirement(ClaimSet.PERMISSION, all_of=perms)


def require_realm_roles(*roles: str, any_of: bool = True) -> AccessRequirement:
    if any_of:
        return AccessRequirement(ClaimSet.REALM_ROLE, any_of=roles)
    return AccessRequirement(ClaimSet.REALM_ROLE, all_of=roles)


def require_client_roles(*roles: str, any_of: bool = True) -> AccessRequirement:
    if any_of:
        return AccessRequirement(ClaimSet.CLIENT_ROLE, any_of=roles)
    return AccessRequirement(ClaimSet.CLIENT_ROLE, all_of=roles)
