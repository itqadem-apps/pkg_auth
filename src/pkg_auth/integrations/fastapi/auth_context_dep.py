"""``make_get_auth_context`` factory.

Composes ``Authentication.get_identity`` (from the authentication
module) with the authorization layer's ``ResolveAuthContextUseCase``,
``SyncUserFromJwtUseCase``, and ``OrganizationRepository`` to produce a
single FastAPI dependency that returns ``(IdentityContext, AuthContext)``.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from ...authentication import IdentityContext
from ...authorization import (
    AuthContext,
    NotAMember,
    OrgId,
    UnknownOrganization,
)
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from ...authorization.domain.ports import OrganizationRepository

DEFAULT_HEADER_NAME = "X-Organization-Id"


def make_get_auth_context(
    *,
    get_identity: Callable[..., Awaitable[IdentityContext]],
    sync_user_use_case: SyncUserFromJwtUseCase,
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    header_name: str = DEFAULT_HEADER_NAME,
) -> Callable[..., Awaitable[tuple[IdentityContext, AuthContext]]]:
    """Build a FastAPI dependency returning ``(IdentityContext, AuthContext)``.

    The dependency:
        1. Resolves identity via the injected ``get_identity``.
        2. Lazily upserts the local user row from JWT claims.
        3. Reads ``header_name`` from the request (numeric → org_id,
           non-numeric → org slug).
        4. Resolves the user's auth context for that organization.

    Errors map to:
        - missing header             → 400
        - unknown organization       → 404
        - user not a member          → 403
    """

    async def dependency(
        request: Request,
        identity: IdentityContext = Depends(get_identity),
    ) -> tuple[IdentityContext, AuthContext]:
        raw = request.headers.get(header_name)
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing {header_name} header",
            )

        user = await sync_user_use_case.execute(
            sub=identity.subject_str,
            email=identity.email_str or "",
            full_name=identity.full_name,
        )

        if raw.isdigit():
            org = await organization_repo.get(OrgId(int(raw)))
        else:
            org = await organization_repo.get_by_slug(raw)
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization {raw!r} not found",
            )

        try:
            auth_ctx = await resolve_use_case.execute(user.id, org.id)
        except NotAMember as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        except UnknownOrganization as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

        return identity, auth_ctx

    return dependency
