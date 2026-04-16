"""Process-wide wiring of pkg_auth dependencies for Django.

Django middleware can't easily inject dependencies the way FastAPI's
``Depends`` system can, so the package wires its use cases as
process-globals during app startup. Call ``install_pkg_auth(...)`` once
in your Django ``AppConfig.ready()`` (or settings) to register the
authentication façade and the use case instances; the middlewares and
decorators read them from this module.

Exactly one of ``sync_user_use_case`` / ``resolve_user_use_case`` must
be supplied — see the ``make_get_auth_context`` FastAPI docstring for
the Mode A vs Mode B distinction.
"""
from __future__ import annotations

from dataclasses import dataclass

from ...authentication import AuthenticateTokenUseCase
from ...authentication.adapters.keycloak import JWTTokenDecoder
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from ...authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from ...authorization.domain.ports import OrganizationRepository


@dataclass(slots=True)
class _PkgAuthRegistry:
    authenticate: AuthenticateTokenUseCase
    resolve_auth: ResolveAuthContextUseCase
    organization_repo: OrganizationRepository
    sync_user: SyncUserFromJwtUseCase | None = None
    resolve_user: ResolveUserFromJwtUseCase | None = None
    cookie_name: str = "access_token"
    header_name: str = "X-Organization-Id"


_REGISTRY: _PkgAuthRegistry | None = None


def install_pkg_auth(
    *,
    keycloak_base_url: str,
    realm: str,
    audience: str,
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    sync_user_use_case: SyncUserFromJwtUseCase | None = None,
    resolve_user_use_case: ResolveUserFromJwtUseCase | None = None,
    cookie_name: str = "access_token",
    header_name: str = "X-Organization-Id",
) -> None:
    """Wire pkg_auth into the Django process.

    Call this exactly once at startup, e.g. from your project's
    ``AppConfig.ready()``. Pass exactly one of ``sync_user_use_case``
    (Mode A — source-of-truth services) or ``resolve_user_use_case``
    (Mode B — consuming services).

    Mode B (most services)::

        from pkg_auth.integrations.django import install_pkg_auth
        from pkg_auth.authorization.adapters.django_orm.repositories import (
            DjangoUserRepository, DjangoOrganizationRepository,
            DjangoMembershipRepository,
        )
        from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import ResolveUserFromJwtUseCase
        from pkg_auth.authorization.application.use_cases.resolve_auth_context import ResolveAuthContextUseCase

        install_pkg_auth(
            keycloak_base_url="https://auth.example.com",
            realm="itqadem",
            audience="courses-service",
            resolve_user_use_case=ResolveUserFromJwtUseCase(
                user_repo=DjangoUserRepository(),
            ),
            resolve_use_case=ResolveAuthContextUseCase(
                membership_repo=DjangoMembershipRepository(),
            ),
            organization_repo=DjangoOrganizationRepository(),
        )

    Mode A (source-of-truth services like ``itq_users``)::

        from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import SyncUserFromJwtUseCase

        install_pkg_auth(
            ...,
            sync_user_use_case=SyncUserFromJwtUseCase(
                user_repo=MyServiceUserRepository(),
            ),
            ...,
        )

    Platform-admin detection is a service-level concern. Cache your
    platform org id at startup (e.g. in this same ``ready()`` hook),
    then call :func:`pkg_auth.authorization.is_platform_context` from
    your views to compare against ``request.auth_context.organization_id``.
    """
    global _REGISTRY

    if (sync_user_use_case is None) == (resolve_user_use_case is None):
        raise ValueError(
            "install_pkg_auth: pass exactly one of "
            "sync_user_use_case (Mode A) or resolve_user_use_case (Mode B)."
        )

    issuer = f"{keycloak_base_url}/realms/{realm}"
    jwks_uri = f"{issuer}/protocol/openid-connect/certs"
    decoder = JWTTokenDecoder(
        jwks_uri=jwks_uri, issuer=issuer, audience=audience,
    )
    _REGISTRY = _PkgAuthRegistry(
        authenticate=AuthenticateTokenUseCase(token_decoder=decoder),
        resolve_auth=resolve_use_case,
        organization_repo=organization_repo,
        sync_user=sync_user_use_case,
        resolve_user=resolve_user_use_case,
        cookie_name=cookie_name,
        header_name=header_name,
    )


def get_registry() -> _PkgAuthRegistry:
    if _REGISTRY is None:
        raise RuntimeError(
            "pkg_auth has not been installed. "
            "Call pkg_auth.integrations.django.install_pkg_auth(...) "
            "from your project's AppConfig.ready()."
        )
    return _REGISTRY
