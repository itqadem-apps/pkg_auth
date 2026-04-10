"""Strawberry context getter producing ``(IdentityContext, AuthContext)``."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from starlette.requests import Request

from ...authentication import (
    AuthenticateTokenUseCase,
    AuthenticationError,
    IdentityContext,
    InvalidTokenError,
    TokenExpiredError,
)
from ...authorization import AuthContext, NotAMember, OrgId
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from ...authorization.domain.ports import OrganizationRepository

DEFAULT_HEADER_NAME = "X-Organization-Id"
DEFAULT_COOKIE_NAME = "access_token"


@dataclass(slots=True)
class StrawberryContext:
    """Context object exposed to every Strawberry resolver via ``info.context``.

    Carries the request, the validated identity (``None`` for anonymous
    queries), and the per-organization authorization context (``None``
    if no ``X-Organization-Id`` header was provided).
    """

    request: Request
    identity: IdentityContext | None = None
    auth_context: AuthContext | None = None
    extra: dict[str, object] = field(default_factory=dict)


def _extract_token(request: Request, cookie_name: str) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if token:
            return token
    return request.cookies.get(cookie_name)


def make_context_getter(
    *,
    authenticate_use_case: AuthenticateTokenUseCase,
    sync_user_use_case: SyncUserFromJwtUseCase,
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    header_name: str = DEFAULT_HEADER_NAME,
    cookie_name: str = DEFAULT_COOKIE_NAME,
) -> Callable[[Request], Awaitable[StrawberryContext]]:
    """Build an async ``context_getter`` for ``strawberry.fastapi.GraphQLRouter``.

    The returned function is permissive: token errors and missing
    headers degrade the context fields to ``None`` rather than raising.
    Permission classes (``IsAuthenticated``, ``RequirePermission``) are
    responsible for rejecting under-privileged queries.
    """

    async def _context_getter(request: Request) -> StrawberryContext:
        ctx = StrawberryContext(request=request)

        token = _extract_token(request, cookie_name)
        if token is not None:
            try:
                ctx.identity = authenticate_use_case.execute(token)
            except (TokenExpiredError, InvalidTokenError, AuthenticationError):
                ctx.identity = None

        if ctx.identity is None:
            return ctx

        raw = request.headers.get(header_name)
        if raw is None:
            return ctx

        user = await sync_user_use_case.execute(
            sub=ctx.identity.subject_str,
            email=ctx.identity.email_str or "",
            full_name=ctx.identity.full_name,
        )

        if raw.isdigit():
            org = await organization_repo.get(OrgId(int(raw)))
        else:
            org = await organization_repo.get_by_slug(raw)
        if org is None:
            return ctx

        try:
            ctx.auth_context = await resolve_use_case.execute(user.id, org.id)
        except NotAMember:
            ctx.auth_context = None

        return ctx

    return _context_getter
