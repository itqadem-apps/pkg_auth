from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence, Type

from graphql import GraphQLError
from starlette.requests import Request
from strawberry.permission import BasePermission
from strawberry.types import Info

from ...domain.entities import AccessContext
from ...domain.exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    AuthenticationError,
    AuthorizationError,
)
from ..common.auth_factory import AuthDependencies, create_auth_dependencies_from_keycloak


# --------------------------------------------------------------------- #
# Context type used by Strawberry
# --------------------------------------------------------------------- #

@dataclass(slots=True)
class StrawberryAuthContext:
    """
    Default context type for Strawberry GraphQL.

    You can use this directly, or extend it in your app by adding more fields.
    """
    request: Request
    user: Optional[AccessContext] = None
    extra: Any = None  # host app can put UoW, services, etc. here if desired


# --------------------------------------------------------------------- #
# Helper: token extraction (header + cookie)
# --------------------------------------------------------------------- #

def _extract_token_from_request(
    request: Request,
    cookie_name: str,
) -> Optional[str]:
    """
    Framework-agnostic token extractor:

      1. Authorization: Bearer <token>
      2. Cookie: cookie_name

    Returns:
        token string or None if not found.
    """
    # 1) Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token

    # 2) Cookie
    cookie_token = request.cookies.get(cookie_name)
    if cookie_token:
        return cookie_token

    return None


# --------------------------------------------------------------------- #
# Main integration: StrawberryAuth
# --------------------------------------------------------------------- #

@dataclass(slots=True)
class StrawberryAuth:
    """
    Strawberry GraphQL integration for pkg_auth.

    Built on top of the framework-agnostic `AuthDependencies` facade.

    Responsibilities:
      - provide a `context_getter` for Strawberry's GraphQLRouter
      - provide permission classes you can attach to fields/mutations

    Token extraction:
      - checks Authorization: Bearer <token>
      - falls back to `cookie_name` (default: "access_token")
    """

    auth: AuthDependencies
    cookie_name: str = "access_token"

    # ----------------------------------------------------------------- #
    # Context getter
    # ----------------------------------------------------------------- #

    def make_context_getter(
        self,
        *,
        optional: bool = True,
        extra_factory: Optional[callable] = None,
    ):
        """
        Build an async function compatible with:

            strawberry.fastapi.GraphQLRouter(context_getter=...)

        Args:
            optional:
                - True:   auth errors become `user=None` in context
                - False:  auth errors become GraphQL errors
            extra_factory:
                - Optional callable: (request: Request, user: AccessContext | None) -> Any
                - Whatever it returns will be stored on context.extra

        Returns:
            async function(request: Request) -> StrawberryAuthContext
        """

        async def _context_getter(request: Request) -> StrawberryAuthContext:
            token = _extract_token_from_request(request, self.cookie_name)

            if not token:
                # No token at all
                if optional:
                    extra = extra_factory(request, None) if extra_factory else None
                    return StrawberryAuthContext(request=request, user=None, extra=extra)
                raise GraphQLError("Not authenticated")

            # There *is* a token -> try to authenticate
            try:
                user = self.auth.authenticate(token)
            except TokenExpiredError:
                if optional:
                    extra = extra_factory(request, None) if extra_factory else None
                    return StrawberryAuthContext(request=request, user=None, extra=extra)
                raise GraphQLError("Token expired")
            except (InvalidTokenError, AuthenticationError) as exc:
                if optional:
                    extra = extra_factory(request, None) if extra_factory else None
                    return StrawberryAuthContext(request=request, user=None, extra=extra)
                raise GraphQLError(str(exc))

            extra = extra_factory(request, user) if extra_factory else None
            return StrawberryAuthContext(request=request, user=user, extra=extra)

        return _context_getter

    # ----------------------------------------------------------------- #
    # Permission helpers
    # ----------------------------------------------------------------- #

    def require_authenticated(self) -> Type[BasePermission]:
        """
        Permission: user must be authenticated (context.user is not None).
        """

        class _RequireAuthenticated(BasePermission):
            message = "Authentication required"

            def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
                ctx: StrawberryAuthContext = info.context
                return ctx.user is not None

        return _RequireAuthenticated

    def require_permissions(self, required: Sequence[str]) -> Type[BasePermission]:
        """
        Permission: user must have ANY of the given permissions.

        Example:

            RequireArticlesRead = strawberry_auth.require_permissions(["articles:read"])

            @strawberry.field(permission_classes=[RequireArticlesRead])
            def articles(self, info: Info) -> list[ArticleType]:
                ...
        """
        auth = self.auth

        class _RequirePermissions(BasePermission):
            message = "Forbidden"

            def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
                ctx: StrawberryAuthContext = info.context
                if not ctx.user:
                    self.message = "Authentication required"
                    return False

                requirement = auth.require_permissions(any_of=list(required))
                try:
                    auth.authorize(ctx.user, [requirement])
                    return True
                except AuthorizationError as exc:
                    self.message = str(exc)
                    return False

        return _RequirePermissions

    def require_realm_roles(self, roles: Iterable[str]) -> Type[BasePermission]:
        """
        Permission: user must have ANY of the given realm roles.

        Example:

            RequireAdmin = strawberry_auth.require_realm_roles(["admin"])

            @strawberry.field(permission_classes=[RequireAdmin])
            def secret_stuff(self, info: Info) -> str:
                ...
        """
        auth = self.auth
        roles_list = list(roles)

        class _RequireRealmRoles(BasePermission):
            message = "Forbidden"

            def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
                ctx: StrawberryAuthContext = info.context
                if not ctx.user:
                    self.message = "Authentication required"
                    return False

                requirement = auth.require_realm_roles(any_of=roles_list)
                try:
                    auth.authorize(ctx.user, [requirement])
                    return True
                except AuthorizationError as exc:
                    self.message = str(exc)
                    return False

        return _RequireRealmRoles

    def require_client_roles(self, roles: Iterable[str]) -> Type[BasePermission]:
        """
        Permission: user must have ANY of the given client roles.

        Example:

            RequireArticlesEditor = strawberry_auth.require_client_roles(
                ["articles:editor", "articles:admin"]
            )
        """
        auth = self.auth
        roles_list = list(roles)

        class _RequireClientRoles(BasePermission):
            message = "Forbidden"

            def has_permission(self, source: Any, info: Info, **kwargs: Any) -> bool:
                ctx: StrawberryAuthContext = info.context
                if not ctx.user:
                    self.message = "Authentication required"
                    return False

                requirement = auth.require_client_roles(any_of=roles_list)
                try:
                    auth.authorize(ctx.user, [requirement])
                    return True
                except AuthorizationError as exc:
                    self.message = str(exc)
                    return False

        return _RequireClientRoles


# --------------------------------------------------------------------- #
# High-level helper: from Keycloak config
# --------------------------------------------------------------------- #

def create_strawberry_auth(
    *,
    keycloak_base_url: str,
    realm: str,
    client_id: str,
    audience: str | None = None,
    cookie_name: str = "access_token",
) -> StrawberryAuth:
    """
    Convenience helper for apps using Keycloak:

        strawberry_auth = create_strawberry_auth(
            keycloak_base_url="https://auth.example.com",
            realm="MyRealm",
            client_id="articles-api",
        )

    This:
      - builds a JWTTokenDecoder from Keycloak config
      - wires AuthenticateTokenUseCase + AuthorizeAccessUseCase
      - wraps them in a StrawberryAuth helper
    """
    auth_deps: AuthDependencies = create_auth_dependencies_from_keycloak(
        keycloak_base_url=keycloak_base_url,
        realm=realm,
        client_id=client_id,
        audience=audience,
    )
    return StrawberryAuth(auth=auth_deps, cookie_name=cookie_name)
