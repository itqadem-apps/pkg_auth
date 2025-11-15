from __future__ import annotations

import asyncio
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, TypeVar, ParamSpec

from fastapi import HTTPException, status
from starlette.requests import Request

from ...domain.exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    AuthenticationError,
    AuthorizationError,
)
from ..common.auth_factory import AuthDependencies
from .security import extract_token_from_request, DEFAULT_COOKIE_NAME

P = ParamSpec("P")
R = TypeVar("R")


@dataclass(slots=True)
class FastAPIDecorators:
    """
    Decorator-based auth helpers for FastAPI route handlers.

    Built on top of the framework-agnostic `AuthDependencies` facade.

    Token extraction strategy:
      - Prefer `Authorization: Bearer <token>` header
      - Fallback to a cookie (default: 'access_token')

    Usage example in your FastAPI app:

        # app/auth.py
        from pkg_auth.integrations.fastapi import create_fastapi_auth
        from app.config import settings

        fastapi_auth = create_fastapi_auth(
            keycloak_base_url=settings.KEYCLOAK_BASE_URL,
            realm=settings.KEYCLOAK_REALM,
            client_id=settings.KEYCLOAK_CLIENT_ID,
        )
        auth_decorators = fastapi_auth.decorators()

        # app/routes.py
        from fastapi import APIRouter, Request
        from pkg_auth import AccessContext
        from app.auth import auth_decorators

        router = APIRouter()

        @router.get("/me")
        @auth_decorators.authenticated
        async def me(request: Request, current_user: AccessContext):
            return {"email": current_user.email}

        @router.get("/articles")
        @auth_decorators.require_permissions("articles:read")
        async def list_articles(request: Request, current_user: AccessContext):
            ...

    All decorators will:
      - Extract the token from Authorization header *or* cookie
      - Authenticate it
      - Optionally authorize against permissions/roles
      - Inject `current_user` (AccessContext) into kwargs
      - Translate domain errors into HTTPException
    """

    auth: AuthDependencies
    cookie_name: str = DEFAULT_COOKIE_NAME  # name of the cookie to fall back to

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_request(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Request:
        """Extract Request object from function arguments."""
        if "request" in kwargs and isinstance(kwargs["request"], Request):
            return kwargs["request"]

        for arg in args:
            if isinstance(arg, Request):
                return arg

        raise ValueError(
            "Request object not found. "
            "Ensure your route has a 'request: Request' parameter."
        )

    def _get_token(self, request: Request) -> str:
        """
        Use the shared extractor to get a token from:
          - Bearer header, or
          - cookie (self.cookie_name)
        """
        return extract_token_from_request(
            request=request,
            credentials=None,        # no HTTPBearer here, decorators work directly with Request
            cookie_name=self.cookie_name,
        )

    def _handle_auth_exceptions(
        self,
        func: Callable[P, R] | Callable[P, Any],
    ) -> Callable[P, Any]:
        """Wrap a function and translate domain auth errors into HTTPException."""

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            try:
                return await func(*args, **kwargs)  # type: ignore[misc]
            except TokenExpiredError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                )
            except InvalidTokenError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                )
            except AuthenticationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                )
            except AuthorizationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(exc),
                )

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except TokenExpiredError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                )
            except InvalidTokenError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                )
            except AuthenticationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                )
            except AuthorizationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(exc),
                )

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    # ------------------------------------------------------------------ #
    # decorators
    # ------------------------------------------------------------------ #

    def authenticated(self, func: Callable[P, R]) -> Callable[P, Any]:
        """
        Decorator: require authentication.

        Injects `current_user: AccessContext` into kwargs.
        """

        @wraps(func)
        async def async_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
            request = self._extract_request(args, kwargs)
            token = self._get_token(request)
            ctx = self.auth.authenticate(token)
            kwargs.setdefault("current_user", ctx)
            return await func(*args, **kwargs)  # type: ignore[misc]

        @wraps(func)
        def sync_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
            request = self._extract_request(args, kwargs)
            token = self._get_token(request)
            ctx = self.auth.authenticate(token)
            kwargs.setdefault("current_user", ctx)
            return func(*args, **kwargs)

        wrapper = async_impl if asyncio.iscoroutinefunction(func) else sync_impl
        return self._handle_auth_exceptions(wrapper)

    def optional_auth(self, func: Callable[P, R]) -> Callable[P, Any]:
        """
        Decorator: optional authentication.

        Injects `current_user: AccessContext | None` into kwargs.
        """

        @wraps(func)
        async def async_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
            request = self._extract_request(args, kwargs)
            try:
                token = self._get_token(request)
            except HTTPException:
                # no token in header or cookie -> anonymous
                kwargs.setdefault("current_user", None)
                return await func(*args, **kwargs)  # type: ignore[misc]

            try:
                ctx = self.auth.authenticate(token)
            except (AuthenticationError, InvalidTokenError, TokenExpiredError):
                ctx = None

            kwargs.setdefault("current_user", ctx)
            return await func(*args, **kwargs)  # type: ignore[misc]

        @wraps(func)
        def sync_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
            request = self._extract_request(args, kwargs)
            try:
                token = self._get_token(request)
            except HTTPException:
                kwargs.setdefault("current_user", None)
                return func(*args, **kwargs)

            try:
                ctx = self.auth.authenticate(token)
            except (AuthenticationError, InvalidTokenError, TokenExpiredError):
                ctx = None

            kwargs.setdefault("current_user", ctx)
            return func(*args, **kwargs)

        wrapper = async_impl if asyncio.iscoroutinefunction(func) else sync_impl
        return self._handle_auth_exceptions(wrapper)

    def require_permissions(self, *permissions: str):
        """
        Decorator: require any of the given permissions.

        Also injects `current_user` into kwargs.
        """

        def decorator(func: Callable[P, R]) -> Callable[P, Any]:
            @wraps(func)
            async def async_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_permissions(any_of=permissions)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return await func(*args, **kwargs)  # type: ignore[misc]

            @wraps(func)
            def sync_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_permissions(any_of=permissions)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return func(*args, **kwargs)

            wrapper = async_impl if asyncio.iscoroutinefunction(func) else sync_impl
            return self._handle_auth_exceptions(wrapper)

        return decorator

    def require_realm_roles(self, *roles: str):
        """
        Decorator: require any of the given realm roles.

        Also injects `current_user` into kwargs.
        """

        def decorator(func: Callable[P, R]) -> Callable[P, Any]:
            @wraps(func)
            async def async_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_realm_roles(any_of=roles)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return await func(*args, **kwargs)  # type: ignore[misc]

            @wraps(func)
            def sync_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_realm_roles(any_of=roles)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return func(*args, **kwargs)

            wrapper = async_impl if asyncio.iscoroutinefunction(func) else sync_impl
            return self._handle_auth_exceptions(wrapper)

        return decorator

    def require_client_roles(self, *roles: str):
        """
        Decorator: require any of the given client roles.

        Also injects `current_user` into kwargs.
        """

        def decorator(func: Callable[P, R]) -> Callable[P, Any]:
            @wraps(func)
            async def async_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_client_roles(any_of=roles)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return await func(*args, **kwargs)  # type: ignore[misc]

            @wraps(func)
            def sync_impl(*args: P.args, **kwargs: P.kwargs) -> Any:
                request = self._extract_request(args, kwargs)
                token = self._get_token(request)
                ctx = self.auth.authenticate(token)

                requirement = self.auth.require_client_roles(any_of=roles)
                self.auth.authorize(ctx, [requirement])

                kwargs.setdefault("current_user", ctx)
                return func(*args, **kwargs)

            wrapper = async_impl if asyncio.iscoroutinefunction(func) else sync_impl
            return self._handle_auth_exceptions(wrapper)

        return decorator


"""
# app/auth.py (example)

from pkg_auth.integrations.fastapi import create_fastapi_auth
from app.config import settings  # your own config

fastapi_auth = create_fastapi_auth(
    keycloak_base_url=settings.KEYCLOAK_BASE_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
)

# Optional: override cookie name if you use a different one
auth_decorators = fastapi_auth.decorators(cookie_name="access_token")

# app/routes.py

from fastapi import APIRouter, Request
from pkg_auth import AccessContext
from app.auth import auth_decorators

router = APIRouter()

@router.get("/me")
@auth_decorators.authenticated
async def me(request: Request, current_user: AccessContext):
    return {"email": current_user.email}

@router.get("/articles")
@auth_decorators.require_permissions("articles:read")
async def list_articles(request: Request, current_user: AccessContext):
    ...

@router.get("/public")
@auth_decorators.optional_auth
async def public_endpoint(request: Request, current_user: AccessContext | None = None):
    # current_user may be None if unauthenticated
    ...
"""
