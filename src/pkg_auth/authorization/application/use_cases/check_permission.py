"""Check that an :class:`AuthContext` grants a specific permission."""
from __future__ import annotations

from dataclasses import dataclass

from ...domain.entities import AuthContext


@dataclass(slots=True)
class CheckPermissionUseCase:
    """Pure wrapper around :meth:`AuthContext.require`.

    Exists as a use case mostly for symmetry with the rest of the
    application layer — most call sites will use ``ctx.require(perm)``
    directly. Provided here for services that prefer a use-case-shaped
    API or want to add cross-cutting behavior (audit logging, metrics)
    via decoration.
    """

    async def execute(self, ctx: AuthContext, perm: str) -> None:
        ctx.require(perm)
