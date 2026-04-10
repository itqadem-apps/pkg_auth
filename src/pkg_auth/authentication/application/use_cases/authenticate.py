"""Authenticate use case: token → IdentityContext."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ...domain.entities import IdentityContext
from ...domain.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
)
from ...domain.ports import TokenDecoder
from ...domain.value_objects import EmailAddress, RealmName, Subject


@dataclass(slots=True)
class AuthenticateTokenUseCase:
    """Decode a token via the injected ``TokenDecoder`` and project its
    claims into an :class:`IdentityContext`.

    This use case knows nothing about authorization, organizations, or
    permissions. It is the single entry point for "who is making this
    request?" — nothing more.
    """

    token_decoder: TokenDecoder

    def execute(self, token: str) -> IdentityContext:
        """Authenticate a token and return the identity it represents.

        Raises:
            TokenExpiredError: token's ``exp`` claim is in the past.
            InvalidTokenError: missing or malformed ``sub``, bad signature,
                or any other verification failure.
            AuthenticationError: unexpected decoder failure.
        """
        try:
            claims = self.token_decoder.decode(token)
        except (TokenExpiredError, InvalidTokenError):
            raise
        except Exception as exc:
            raise AuthenticationError(f"Token validation failed: {exc}") from exc

        return self._build_identity(claims)

    @staticmethod
    def _build_identity(claims: Mapping[str, Any]) -> IdentityContext:
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise InvalidTokenError("Token is missing required `sub` claim")

        email_raw = claims.get("email")
        email: EmailAddress | None = None
        if isinstance(email_raw, str) and "@" in email_raw:
            email = EmailAddress(email_raw)

        realm: RealmName | None = None
        iss = claims.get("iss")
        if isinstance(iss, str) and "/realms/" in iss:
            realm = RealmName(iss.rsplit("/realms/", 1)[-1])

        session_id_raw = claims.get("sid") or claims.get("session_state")
        session_id: str | None = (
            session_id_raw if isinstance(session_id_raw, str) else None
        )

        return IdentityContext(
            subject=Subject(sub),
            email=email,
            email_verified=bool(claims.get("email_verified") or False),
            full_name=_str_or_none(claims.get("name")),
            first_name=_str_or_none(claims.get("given_name")),
            last_name=_str_or_none(claims.get("family_name")),
            preferred_username=_str_or_none(claims.get("preferred_username")),
            realm=realm,
            session_id=session_id,
            issued_at=_int_or_none(claims.get("iat")),
            expires_at=_int_or_none(claims.get("exp")),
            auth_time=_int_or_none(claims.get("auth_time")),
        )


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None
