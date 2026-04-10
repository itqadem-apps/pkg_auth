from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Callable, TypeVar

from django.http import HttpRequest, HttpResponse, JsonResponse

from ..common.auth_factory import AuthDependencies, create_auth_dependencies_from_keycloak
from ...domain.entities import AccessContext
from ...domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
    TokenExpiredError,
)

DEFAULT_COOKIE_NAME = "access_token"

TView = TypeVar("TView", bound=Callable[..., HttpResponse])


def _extract_bearer_from_authorization_header(value: str) -> str | None:
    if not value:
        return None
    parts = value.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip(), parts[1].strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def extract_token_from_request(
    request: HttpRequest,
    *,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> str:
    """
    Extract an access token from a Django request.

    Supported sources:
    - Authorization header: `Bearer <token>`
    - Cookie: `<cookie_name>`
    """
    header = request.META.get("HTTP_AUTHORIZATION") or ""
    token = _extract_bearer_from_authorization_header(header)
    if token:
        return token

    token = request.COOKIES.get(cookie_name)
    if token:
        return token

    raise AuthenticationError("Missing access token")


def _json_error(detail: str, *, status: int) -> JsonResponse:
    return JsonResponse({"detail": detail}, status=status)


@dataclass(slots=True)
class DjangoAuthorization:
    """
    Django integration for pkg_auth.

    - Auth helpers: token -> AccessContext
    - Decorators to guard Django views
    - Attaches authenticated context to `request.access_context`
    """

    auth: AuthDependencies

    def get_current_user(
        self,
        request: HttpRequest,
        *,
        cookie_name: str = DEFAULT_COOKIE_NAME,
    ) -> AccessContext:
        token = extract_token_from_request(request, cookie_name=cookie_name)
        return self.auth.authenticate(token)

    def get_optional_user(
        self,
        request: HttpRequest,
        *,
        cookie_name: str = DEFAULT_COOKIE_NAME,
    ) -> AccessContext | None:
        try:
            token = extract_token_from_request(request, cookie_name=cookie_name)
        except AuthenticationError:
            return None

        try:
            return self.auth.authenticate(token)
        except (TokenExpiredError, InvalidTokenError, AuthenticationError):
            return None

    def require_auth(
        self,
        *,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        json: bool = True,
    ) -> Callable[[TView], TView]:
        def decorator(view_func: TView) -> TView:
            @wraps(view_func)
            def wrapped(request: HttpRequest, *args, **kwargs):
                try:
                    ctx = self.get_current_user(request, cookie_name=cookie_name)
                except TokenExpiredError:
                    return (
                        _json_error("Token expired", status=401)
                        if json
                        else HttpResponse("Token expired", status=401)
                    )
                except (InvalidTokenError, AuthenticationError) as exc:
                    return (
                        _json_error(str(exc), status=401)
                        if json
                        else HttpResponse(str(exc), status=401)
                    )

                setattr(request, "access_context", ctx)
                return view_func(request, *args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator

    def require_permissions(
        self,
        *permissions: str,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        json: bool = True,
    ) -> Callable[[TView], TView]:
        def decorator(view_func: TView) -> TView:
            @self.require_auth(cookie_name=cookie_name, json=json)
            @wraps(view_func)
            def wrapped(request: HttpRequest, *args, **kwargs):
                ctx: AccessContext = request.access_context  # type: ignore[attr-defined]
                requirement = self.auth.require_permissions(any_of=permissions)
                try:
                    self.auth.authorize(ctx, [requirement])
                except AuthorizationError as exc:
                    return (
                        _json_error(str(exc), status=403)
                        if json
                        else HttpResponse(str(exc), status=403)
                    )
                return view_func(request, *args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator

    def require_realm_roles(
        self,
        *roles: str,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        json: bool = True,
    ) -> Callable[[TView], TView]:
        def decorator(view_func: TView) -> TView:
            @self.require_auth(cookie_name=cookie_name, json=json)
            @wraps(view_func)
            def wrapped(request: HttpRequest, *args, **kwargs):
                ctx: AccessContext = request.access_context  # type: ignore[attr-defined]
                requirement = self.auth.require_realm_roles(any_of=roles)
                try:
                    self.auth.authorize(ctx, [requirement])
                except AuthorizationError as exc:
                    return (
                        _json_error(str(exc), status=403)
                        if json
                        else HttpResponse(str(exc), status=403)
                    )
                return view_func(request, *args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator

    def require_client_roles(
        self,
        *roles: str,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        json: bool = True,
    ) -> Callable[[TView], TView]:
        def decorator(view_func: TView) -> TView:
            @self.require_auth(cookie_name=cookie_name, json=json)
            @wraps(view_func)
            def wrapped(request: HttpRequest, *args, **kwargs):
                ctx: AccessContext = request.access_context  # type: ignore[attr-defined]
                requirement = self.auth.require_client_roles(any_of=roles)
                try:
                    self.auth.authorize(ctx, [requirement])
                except AuthorizationError as exc:
                    return (
                        _json_error(str(exc), status=403)
                        if json
                        else HttpResponse(str(exc), status=403)
                    )
                return view_func(request, *args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator


def create_django_auth(
    *,
    keycloak_base_url: str,
    realm: str,
    client_id: str,
    audience: str | None = None,
) -> DjangoAuthorization:
    auth: AuthDependencies = create_auth_dependencies_from_keycloak(
        keycloak_base_url=keycloak_base_url,
        realm=realm,
        client_id=client_id,
        audience=audience,
    )
    return DjangoAuthorization(auth=auth)
