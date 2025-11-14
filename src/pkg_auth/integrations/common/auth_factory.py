from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from ...adapters.keycloak.jwt_decoder import JWTTokenDecoder
from ...application.use_cases.authenticate import AuthenticateTokenUseCase
from ...application.use_cases.authorize import AuthorizeAccessUseCase
from ...domain.constants import ClaimSet
from ...domain.entities import AccessContext
from ...domain.ports import TokenDecoder
from ...domain.value_objects import AccessRequirement


@dataclass(slots=True)
class AuthDependencies:
    """
    Framework-agnostic auth facade.

    Integrations (FastAPI, Strawberry, etc.) adapt this to their own
    dependency / decorator systems.
    """

    auth_use_case: AuthenticateTokenUseCase
    authorize_use_case: AuthorizeAccessUseCase

    # --- Core operations --------------------------------------------------

    def authenticate(self, token: str) -> AccessContext:
        """Token -> AccessContext (or raise auth exceptions)."""
        return self.auth_use_case.execute(token)

    def authorize(
            self,
            context: AccessContext,
            requirements: Iterable[AccessRequirement],
    ) -> AccessContext:
        """Check requirements on an existing AccessContext."""
        return self.authorize_use_case.execute(context, requirements)

    # --- Convenience helpers to build requirements ------------------------

    def require_permissions(
            self,
            *,
            any_of: Sequence[str] = (),
            all_of: Sequence[str] = (),
    ) -> AccessRequirement:
        return AccessRequirement(
            claim_set=ClaimSet.PERMISSION,
            any_of=any_of,
            all_of=all_of,
        )

    def require_realm_roles(
            self,
            *,
            any_of: Sequence[str] = (),
            all_of: Sequence[str] = (),
    ) -> AccessRequirement:
        return AccessRequirement(
            claim_set=ClaimSet.REALM_ROLE,
            any_of=any_of,
            all_of=all_of,
        )

    def require_client_roles(
            self,
            *,
            any_of: Sequence[str] = (),
            all_of: Sequence[str] = (),
    ) -> AccessRequirement:
        return AccessRequirement(
            claim_set=ClaimSet.CLIENT_ROLE,
            any_of=any_of,
            all_of=all_of,
        )


def create_auth_dependencies_from_keycloak(
        *,
        keycloak_base_url: str,
        realm: str,
        client_id: str,
        audience: str | None = None,
) -> AuthDependencies:
    """
    High-level factory: Keycloak config -> AuthDependencies.

    This matches the spirit of your old `create_auth_dependencies`:
    - builds a JWTTokenDecoder
    - wires AuthenticateTokenUseCase + AuthorizeAccessUseCase
    - returns an AuthDependencies facade.
    """
    issuer = f"{keycloak_base_url}/realms/{realm}"
    jwks_uri = f"{issuer}/protocol/openid-connect/certs"

    decoder: TokenDecoder = JWTTokenDecoder(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience or client_id,
    )

    auth_uc = AuthenticateTokenUseCase(
        token_decoder=decoder,
        client_id=client_id,
    )
    authorize_uc = AuthorizeAccessUseCase()

    return AuthDependencies(
        auth_use_case=auth_uc,
        authorize_use_case=authorize_uc,
    )
