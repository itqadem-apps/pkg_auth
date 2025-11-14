from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any, Set

from ...domain.entities import AccessContext, IdentityInfo, SessionInfo, AccessRights
from ...domain.exceptions import TokenExpiredError, InvalidTokenError, AuthenticationError
from ...domain.ports import TokenDecoder
from ...domain.value_objects import Subject, EmailAddress, RealmName


@dataclass(slots=True)
class AuthenticateTokenUseCase:
    """
    Application use case:
    - Decode a token via TokenDecoder port
    - Map Keycloak claims -> AccessContext

    Framework-agnostic, but Keycloak-aware.

    `client_id` is the Keycloak client for *this* service, and we will
    only use roles from that client in `client_roles` and `permissions`.
    """

    token_decoder: TokenDecoder
    client_id: str  # Keycloak client id for this service

    def execute(self, token: str) -> AccessContext:
        """
        Authenticate a token and return an AccessContext.

        Raises:
            TokenExpiredError
            InvalidTokenError
            AuthenticationError
        """
        try:
            claims = self.token_decoder.decode(token)
        except (TokenExpiredError, InvalidTokenError):
            # let callers distinguish these explicitly
            raise
        except Exception as exc:
            # Wrap unexpected errors in a generic AuthenticationError
            raise AuthenticationError(f"Token validation failed: {exc}") from exc

        return self._build_context_from_claims(claims)

    # ------------------------------------------------------------------ #
    # Internal: claims -> AccessContext mapping (Keycloak-specific)
    # ------------------------------------------------------------------ #

    def _build_context_from_claims(self, claims: Mapping[str, Any]) -> AccessContext:
        # ---- Identity -----------------------------------------------------
        sub = claims.get("sub")
        email = claims.get("email")

        identity = IdentityInfo(
            subject=Subject(sub) if sub is not None else None,
            email=EmailAddress(email) if email is not None else None,
            email_verified=bool(claims.get("email_verified") or False),
            full_name=claims.get("name"),
            first_name=claims.get("given_name"),
            last_name=claims.get("family_name"),
            preferred_username=claims.get("preferred_username"),
        )

        # ---- Session ------------------------------------------------------
        iss = claims.get("iss")
        realm_vo: RealmName | None = None
        if isinstance(iss, str) and "/realms/" in iss:
            # e.g. "https://auth.example.com/realms/MyRealm"
            realm_str = iss.rsplit("/realms/", 1)[-1]
            realm_vo = RealmName(realm_str)

        session = SessionInfo(
            session_id=claims.get("sid") or claims.get("session_state"),
            issued_at=claims.get("iat"),
            expires_at=claims.get("exp"),
            auth_time=claims.get("auth_time"),
            realm=realm_vo,
        )

        # ---- Access rights: scopes & audiences ---------------------------
        scope_raw = claims.get("scope") or ""
        scopes: Set[str] = set(scope_raw.split()) if scope_raw else set()

        aud_raw = claims.get("aud") or []
        if isinstance(aud_raw, str):
            audiences: Set[str] = {aud_raw}
        else:
            audiences = set(aud_raw)

        # ---- Roles --------------------------------------------------------
        realm_roles = set(
            (claims.get("realm_access") or {}).get("roles", []) or []
        )

        resource_access = claims.get("resource_access") or {}

        # Only roles for *this* client (service)
        client_data = resource_access.get(self.client_id) or {}
        client_roles: Set[str] = set(client_data.get("roles") or [])

        # In this generic package, "permissions" = roles for this client.
        permissions = set(client_roles)

        rights = AccessRights(
            scopes=scopes,
            audiences=audiences,
            realm_roles=realm_roles,
            client_roles=client_roles,
            permissions=permissions,
        )

        return AccessContext(identity=identity, session=session, rights=rights)
