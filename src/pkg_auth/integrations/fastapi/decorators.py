"""``require_permission`` Depends-wrapper for FastAPI routes."""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Depends, HTTPException, status

from ...authentication import IdentityContext
from ...authorization import AuthContext, MissingPermission


def require_permission(
    perm: str,
    *,
    get_auth_context: Callable[
        ..., Awaitable[tuple[IdentityContext, AuthContext]]
    ],
) -> Callable[..., Awaitable[tuple[IdentityContext, AuthContext]]]:
    """Build a FastAPI dependency that enforces a single permission.

    Usage on a single handler::

        @router.post("/courses/{id}/publish")
        async def publish(
            id: str,
            bundle = Depends(require_permission(
                "course:publish", get_auth_context=get_auth_context,
            )),
        ): ...

    Or as a route-level dependency (no kwarg in the handler signature)::

        @router.post(
            "/courses/{id}/publish",
            dependencies=[Depends(require_permission(
                "course:publish", get_auth_context=get_auth_context,
            ))],
        )
        async def publish(id: str): ...
    """

    async def dependency(
        bundle: tuple[IdentityContext, AuthContext] = Depends(get_auth_context),
    ) -> tuple[IdentityContext, AuthContext]:
        _, auth_ctx = bundle
        try:
            auth_ctx.require(perm)
        except MissingPermission as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        return bundle

    return dependency
