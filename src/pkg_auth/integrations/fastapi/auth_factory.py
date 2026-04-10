"""Authentication façade and factory for FastAPI services."""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from ...authentication import (
    AuthenticateTokenUseCase,
    AuthenticationError,
    IdentityContext,
    InvalidTokenError,
    TokenExpiredError,
)
from ...authentication.adapters.keycloak import JWTTokenDecoder
from .identity_dep import (
    DEFAULT_COOKIE_NAME,
    bearer_scheme,
    extract_token_from_request,
)


@dataclass(slots=True)
class Authentication:
    """FastAPI-side façade over the pure ``AuthenticateTokenUseCase``.

    Exposes a single dependency, :meth:`get_identity`, which validates
    a JWT and returns an :class:`IdentityContext`. **Authorization is
    handled separately** via the auth_context dependency from the
    authorization module — this façade does identity only.
    """

    use_case: AuthenticateTokenUseCase
    cookie_name: str = DEFAULT_COOKIE_NAME

    async def get_identity(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    ) -> IdentityContext:
        """Dependency: require a valid Keycloak token, return ``IdentityContext``."""
        try:
            token = extract_token_from_request(
                request, credentials, cookie_name=self.cookie_name,
            )
            return self.use_case.execute(token)
        except TokenExpiredError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
            ) from exc
        except (InvalidTokenError, AuthenticationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc


def create_authentication(
    *,
    keycloak_base_url: str,
    realm: str,
    audience: str,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> Authentication:
    """High-level helper: build an :class:`Authentication` from Keycloak config.

    The ``audience`` is the Keycloak client ID this service expects in
    the ``aud`` claim. There is no longer a separate ``client_id``
    parameter because authorization no longer reads claims —
    authorization comes from the ACL database via the authorization
    module.
    """
    issuer = f"{keycloak_base_url}/realms/{realm}"
    jwks_uri = f"{issuer}/protocol/openid-connect/certs"

    decoder = JWTTokenDecoder(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience,
    )
    use_case = AuthenticateTokenUseCase(token_decoder=decoder)
    return Authentication(use_case=use_case, cookie_name=cookie_name)
