"""App-wide exception handlers for pkg_auth domain errors."""
from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from ...authentication import (
    AuthenticationError,
    InvalidTokenError,
    TokenExpiredError,
)
from ...authorization import (
    AuthorizationError,
    MissingPermission,
    NotAMember,
    UnknownOrganization,
    UnknownPermission,
    UnknownRole,
    UnknownUser,
)


def install_exception_handlers(app: FastAPI) -> None:
    """Register catch-all handlers for pkg_auth domain exceptions.

    Mappings:
        TokenExpiredError       → 401
        InvalidTokenError       → 401
        AuthenticationError     → 401
        NotAMember              → 403
        MissingPermission       → 403
        AuthorizationError      → 403 (catch-all for the hierarchy)
        UnknownOrganization     → 404
        UnknownUser             → 404
        UnknownRole             → 404
        UnknownPermission       → 404

    Services that prefer per-route ``try/except`` can simply not call
    this. The deps and decorators in this package raise ``HTTPException``
    directly so they work either way.
    """

    async def _401(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": str(exc)},
        )

    async def _403(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": str(exc)},
        )

    async def _404(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": str(exc)},
        )

    app.add_exception_handler(TokenExpiredError, _401)
    app.add_exception_handler(InvalidTokenError, _401)
    app.add_exception_handler(AuthenticationError, _401)

    app.add_exception_handler(NotAMember, _403)
    app.add_exception_handler(MissingPermission, _403)
    app.add_exception_handler(AuthorizationError, _403)

    app.add_exception_handler(UnknownOrganization, _404)
    app.add_exception_handler(UnknownUser, _404)
    app.add_exception_handler(UnknownRole, _404)
    app.add_exception_handler(UnknownPermission, _404)
