"""Django integration for pkg_auth (identity + ACL).

Provides:
    - ``IdentityMiddleware``     — validates JWT, attaches ``request.identity``
    - ``AuthContextMiddleware``  — reads ``X-Organization-Id``, attaches ``request.auth_context``
    - ``require_permission``     — function decorator for Django views
    - ``install_pkg_auth``       — convenience wiring helper

Add ``"pkg_auth.integrations.django"`` to ``INSTALLED_APPS`` and the
two middlewares to ``MIDDLEWARE`` (in order — identity first).
"""
from __future__ import annotations

try:
    import django  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pkg_auth.integrations.django requires Django. "
        "Install with: pip install pkg-auth[django]"
    ) from exc

from .auth_context_middleware import AuthContextMiddleware
from .decorators import require_permission
from .install import install_pkg_auth
from .middleware import IdentityMiddleware

__all__ = [
    "IdentityMiddleware",
    "AuthContextMiddleware",
    "require_permission",
    "install_pkg_auth",
]
