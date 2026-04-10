"""``@require_permission`` function decorator for Django views."""
from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable

from asgiref.sync import iscoroutinefunction
from django.http import HttpRequest, HttpResponse, JsonResponse

from ...authorization import MissingPermission


def require_permission(
    perm: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: require ``perm`` on ``request.auth_context``.

    Requires ``IdentityMiddleware`` and ``AuthContextMiddleware`` to be
    installed in ``MIDDLEWARE``. The decorator does NOT do its own JWT
    validation — that's the middleware's job.

    Returns 401 if there's no identity, 403 if the perm is missing.

    Works for both sync and async views.

    Example::

        @require_permission("course:edit")
        async def edit_course(request, course_id):
            ...
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        if iscoroutinefunction(view):

            @functools.wraps(view)
            async def async_wrapper(
                request: HttpRequest, *args: Any, **kwargs: Any
            ) -> HttpResponse:
                err = _check(request, perm)
                if err is not None:
                    return err
                return await view(request, *args, **kwargs)

            return async_wrapper

        @functools.wraps(view)
        def sync_wrapper(
            request: HttpRequest, *args: Any, **kwargs: Any
        ) -> HttpResponse:
            err = _check(request, perm)
            if err is not None:
                return err
            return view(request, *args, **kwargs)

        return sync_wrapper

    return decorator


def _check(request: HttpRequest, perm: str) -> HttpResponse | None:
    auth_ctx = getattr(request, "auth_context", None)
    if auth_ctx is None:
        identity = getattr(request, "identity", None)
        if identity is None:
            return JsonResponse({"detail": "Not authenticated"}, status=401)
        return JsonResponse(
            {"detail": "Missing X-Organization-Id header"}, status=400,
        )
    try:
        auth_ctx.require(perm)
    except MissingPermission as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    return None
