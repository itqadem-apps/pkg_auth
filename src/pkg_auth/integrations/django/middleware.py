"""IdentityMiddleware — validates JWT, attaches ``request.identity``."""
from __future__ import annotations

from typing import Awaitable, Callable

from asgiref.sync import iscoroutinefunction
from django.http import HttpRequest, HttpResponse, JsonResponse

from ...authentication import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
)
from .install import get_registry


def _extract_token(request: HttpRequest, cookie_name: str) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token
    cookie_token = request.COOKIES.get(cookie_name)
    if cookie_token:
        return cookie_token
    return None


class IdentityMiddleware:
    """Lazy JWT validation. Attaches ``request.identity`` (or ``None``).

    On routes that don't require auth, this middleware is a no-op when
    no token is present (``request.identity = None``). On routes that
    DO require auth, the route's decorator / dependency raises 401
    when ``request.identity`` is ``None``.

    Token validation errors are NOT raised here — they set
    ``request.identity = None`` and let the auth decorator decide. This
    keeps the middleware out of the response path for anonymous routes.
    """

    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response: Callable[
            [HttpRequest], HttpResponse | Awaitable[HttpResponse]
        ],
    ) -> None:
        self.get_response = get_response
        self._async = iscoroutinefunction(get_response)

    def __call__(self, request: HttpRequest) -> HttpResponse | Awaitable[HttpResponse]:
        registry = get_registry()
        token = _extract_token(request, registry.cookie_name)
        request.identity = None  # type: ignore[attr-defined]
        if token is not None:
            try:
                request.identity = registry.authenticate.execute(token)  # type: ignore[attr-defined]
            except (TokenExpiredError, InvalidTokenError, AuthenticationError):
                request.identity = None  # type: ignore[attr-defined]
        return self.get_response(request)
