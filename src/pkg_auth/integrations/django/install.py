"""Process-wide wiring of pkg_auth dependencies for Django.

Django middleware can't easily inject dependencies the way FastAPI's
``Depends`` system can, so the package wires its use cases as
process-globals during app startup. Call ``install_pkg_auth(...)`` once
in your Django ``AppConfig.ready()`` (or settings) to register the
authentication façade and the use case instances; the middlewares and
decorators read them from this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from ...authentication import AuthenticateTokenUseCase
from ...authentication.adapters.keycloak import JWTTokenDecoder
from ...authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from ...authorization.application.use_cases.sync_user_from_jwt import (
    SyncUserFromJwtUseCase,
)
from ...authorization.domain.ports import OrganizationRepository


@dataclass(slots=True)
class _PkgAuthRegistry:
    authenticate: AuthenticateTokenUseCase
    sync_user: SyncUserFromJwtUseCase
    resolve_auth: ResolveAuthContextUseCase
    organization_repo: OrganizationRepository
    cookie_name: str = "access_token"
    header_name: str = "X-Organization-Id"


_REGISTRY: _PkgAuthRegistry | None = None


def install_pkg_auth(
    *,
    keycloak_base_url: str,
    realm: str,
    audience: str,
    sync_user_use_case: SyncUserFromJwtUseCase,
    resolve_use_case: ResolveAuthContextUseCase,
    organization_repo: OrganizationRepository,
    cookie_name: str = "access_token",
    header_name: str = "X-Organization-Id",
) -> None:
    """Wire pkg_auth into the Django process.

    Call this exactly once at startup, e.g. from your project's
    ``AppConfig.ready()``::

        from pkg_auth.integrations.django import install_pkg_auth
        from pkg_auth.authorization.adapters.django_orm.repositories import (
            DjangoUserRepository, DjangoOrganizationRepository,
        )
        from pkg_auth.authorization.application.use_cases.sync_user_from_jwt import SyncUserFromJwtUseCase
        from pkg_auth.authorization.application.use_cases.resolve_auth_context import ResolveAuthContextUseCase

        org_repo = DjangoOrganizationRepository()
        install_pkg_auth(
            keycloak_base_url="https://auth.example.com",
            realm="itqadem",
            audience="courses-service",
            sync_user_use_case=SyncUserFromJwtUseCase(
                user_repo=DjangoUserRepository(),
            ),
            resolve_use_case=ResolveAuthContextUseCase(
                membership_repo=DjangoMembershipRepository(),
            ),
            organization_repo=org_repo,
        )
    """
    global _REGISTRY

    issuer = f"{keycloak_base_url}/realms/{realm}"
    jwks_uri = f"{issuer}/protocol/openid-connect/certs"
    decoder = JWTTokenDecoder(
        jwks_uri=jwks_uri, issuer=issuer, audience=audience,
    )
    _REGISTRY = _PkgAuthRegistry(
        authenticate=AuthenticateTokenUseCase(token_decoder=decoder),
        sync_user=sync_user_use_case,
        resolve_auth=resolve_use_case,
        organization_repo=organization_repo,
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
