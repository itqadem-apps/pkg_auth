"""Strawberry permission classes built on ``StrawberryContext``."""
from __future__ import annotations

from typing import Any

from strawberry.permission import BasePermission
from strawberry.types import Info

from .auth import StrawberryContext


class IsAuthenticated(BasePermission):
    """Permission class: require a valid identity (any organization or none)."""

    message = "Authentication required"

    async def has_permission(
        self, source: Any, info: Info, **kwargs: Any
    ) -> bool:
        ctx: StrawberryContext = info.context
        return ctx.identity is not None


class RequirePermission(BasePermission):
    """Permission class: require a specific perm in the active org context.

    Usage::

        @strawberry.type
        class Query:
            @strawberry.field(
                permission_classes=[RequirePermission("course:view")],
            )
            async def course(self, id: strawberry.ID) -> Course: ...

    Returns ``False`` (and a meaningful ``message``) when:
        - the request has no identity → "Authentication required"
        - the request has identity but no auth_context → "Missing X-Organization-Id"
        - the role does not grant ``perm`` → "Permission denied: <perm>"
    """

    def __init__(self, perm: str) -> None:
        self.perm = perm
        self.message = f"Permission denied: {perm}"

    async def has_permission(
        self, source: Any, info: Info, **kwargs: Any
    ) -> bool:
        ctx: StrawberryContext = info.context
        if ctx.identity is None:
            self.message = "Authentication required"
            return False
        if ctx.auth_context is None:
            self.message = "Missing X-Organization-Id header"
            return False
        return ctx.auth_context.has(self.perm)
