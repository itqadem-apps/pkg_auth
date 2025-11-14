from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials

from .security import bearer_scheme, extract_token_from_request
from ..common.auth_factory import AuthDependencies
from ...domain.entities import AccessContext
from ...domain.exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    AuthenticationError,
    AuthorizationError,
)


@dataclass(slots=True)
class FastAPIAuthorization:
    """
    FastAPI integration for pkg_auth.

    This replaces your old AuthDependencies class, but built on top of the
    framework-agnostic AuthDependencies facade.
    """

    auth: AuthDependencies

    # ------------------------------------------------------------------ #
    # Base dependencies
    # ------------------------------------------------------------------ #

    async def get_current_user(
            self,
            request: Request,
            credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    ) -> AccessContext:
        """Dependency: Require authentication."""
        try:
            token = extract_token_from_request(request, credentials)
            return self.auth.authenticate(token)
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

    async def get_optional_user(
            self,
            request: Request,
            credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    ) -> AccessContext | None:
        """Dependency: Optional authentication."""
        try:
            token = extract_token_from_request(request, credentials)
        except HTTPException:
            # no token anywhere -> anonymous
            return None

        try:
            return self.auth.authenticate(token)
        except (TokenExpiredError, InvalidTokenError, AuthenticationError):
            # bad token -> treat as anonymous (or change to 401 if you prefer)
            return None

    # ------------------------------------------------------------------ #
    # Authorization dependency factories
    # ------------------------------------------------------------------ #

    def require_permissions(self, *permissions: str) -> Callable:
        """
        Dependency factory: require any of the given permissions.
        """

        async def dependency(
                ctx: AccessContext = Depends(self.get_current_user),
        ) -> AccessContext:
            requirement = self.auth.require_permissions(any_of=permissions)
            try:
                self.auth.authorize(ctx, [requirement])
                return ctx
            except AuthorizationError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=str(exc)) from exc

        return dependency

    def require_realm_roles(self, *roles: str) -> Callable:
        """
        Dependency factory: require any of the given realm roles.
        """

        async def dependency(
                ctx: AccessContext = Depends(self.get_current_user),
        ) -> AccessContext:
            requirement = self.auth.require_realm_roles(any_of=roles)
            try:
                self.auth.authorize(ctx, [requirement])
                return ctx
            except AuthorizationError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=str(exc)) from exc

        return dependency

    def require_client_roles(self, *roles: str) -> Callable:
        """
        Dependency factory: require any of the given client roles.
        """

        async def dependency(
                ctx: AccessContext = Depends(self.get_current_user),
        ) -> AccessContext:
            requirement = self.auth.require_client_roles(any_of=roles)
            try:
                self.auth.authorize(ctx, [requirement])
                return ctx
            except AuthorizationError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=str(exc)) from exc

        return dependency


"""

from pkg_auth.integrations.fastapi import create_fastapi_auth
from app.config import settings  # your own settings

fastapi_auth = create_fastapi_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
)

get_current_user = fastapi_auth.get_current_user
get_optional_user = fastapi_auth.get_optional_user
require_permissions = fastapi_auth.require_permissions
require_realm_roles = fastapi_auth.require_realm_roles
require_client_roles = fastapi_auth.require_client_roles


"""
