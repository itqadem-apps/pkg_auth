"""Identity value objects (subject, email, realm name)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Subject:
    """The IdP subject identifier (Keycloak ``sub`` claim).

    Kept as a distinct type so it isn't accidentally treated as an
    internal user primary key.
    """

    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class EmailAddress:
    """An email address with light validation."""

    value: str

    def __post_init__(self) -> None:
        if "@" not in self.value:
            raise ValueError(f"Invalid email address: {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RealmName:
    """A Keycloak realm name extracted from an issuer URL."""

    value: str

    def __str__(self) -> str:
        return self.value
