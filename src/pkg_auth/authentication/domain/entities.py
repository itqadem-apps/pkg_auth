"""Identity context — the validated output of token authentication.

This is the only entity exposed by the authentication module. It carries
identity and session metadata; it does NOT carry authorization rights.
Authorization is derived per-(user, organization) by the
``pkg_auth.authorization`` module from a real ACL database.
"""
from __future__ import annotations

from dataclasses import dataclass

from .value_objects import EmailAddress, RealmName, Subject


@dataclass(frozen=True, slots=True)
class IdentityContext:
    """Identity and session metadata for an authenticated principal.

    Built from JWT claims by :class:`AuthenticateTokenUseCase`. Frozen
    because it's a snapshot of the token at the moment of validation —
    it never mutates after construction.

    The ``subject`` field is required: a JWT without a ``sub`` claim is
    rejected as ``InvalidTokenError`` before this object is built.
    """

    subject: Subject
    email: EmailAddress | None = None
    email_verified: bool = False

    full_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    preferred_username: str | None = None

    realm: RealmName | None = None
    session_id: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    auth_time: int | None = None

    @property
    def email_str(self) -> str | None:
        """The email as a plain string, or ``None`` if unset."""
        return str(self.email) if self.email is not None else None

    @property
    def subject_str(self) -> str:
        """The subject as a plain string."""
        return str(self.subject)
