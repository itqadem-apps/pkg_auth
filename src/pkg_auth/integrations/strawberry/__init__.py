"""Strawberry GraphQL integration for pkg_auth (identity + ACL)."""
from __future__ import annotations

try:
    import strawberry  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.integrations.strawberry requires strawberry-graphql. "
        "Install with: pip install pkg-auth[strawberry]"
    ) from exc

from .auth import StrawberryContext, make_context_getter
from .permissions import IsAuthenticated, RequirePermission

__all__ = [
    "StrawberryContext",
    "make_context_getter",
    "IsAuthenticated",
    "RequirePermission",
]
