"""Wire pkg_auth.authentication + .authorization + cache + integrations.fastapi."""
from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from pkg_auth.authorization.adapters.cache import (
    CachedMembershipRepository,
    InMemoryTTLCache,
)
from pkg_auth.authorization.adapters.sqlalchemy import (
    SqlAlchemyMembershipRepository,
    SqlAlchemyOrganizationRepository,
    SqlAlchemyPermissionCatalogRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemyUserRepository,
)
from pkg_auth.authorization.application.use_cases.register_permission_catalog import (
    RegisterPermissionCatalogUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_auth_context import (
    ResolveAuthContextUseCase,
)
from pkg_auth.authorization.application.use_cases.resolve_user_from_jwt import (
    ResolveUserFromJwtUseCase,
)
from pkg_auth.integrations.fastapi import (
    Authentication,
    create_authentication,
    install_exception_handlers,
    make_get_auth_context,
    require_permission,
)

# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #

DATABASE_URL = os.environ.get(
    "ACL_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/itqadem_acl",
)
_engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)

# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #

_authentication: Authentication = create_authentication(
    keycloak_base_url=os.environ["KEYCLOAK_BASE_URL"],
    realm=os.environ["KEYCLOAK_REALM"],
    audience=os.environ["KEYCLOAK_AUDIENCE"],  # this service's client_id
)
get_identity = _authentication.get_identity

# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #

# Cache the hot-path membership repo. The InMemoryTTLCache is per-process
# and zero-deps; swap for RedisCache when you need cache coherence across
# multiple replicas.
_cache = InMemoryTTLCache(max_entries=10_000)

user_repo = SqlAlchemyUserRepository(session_factory=_session_factory)
organization_repo = SqlAlchemyOrganizationRepository(session_factory=_session_factory)
role_repo = SqlAlchemyRoleRepository(session_factory=_session_factory)
catalog_repo = SqlAlchemyPermissionCatalogRepository(session_factory=_session_factory)
membership_repo = CachedMembershipRepository(
    inner=SqlAlchemyMembershipRepository(session_factory=_session_factory),
    cache=_cache,
    ttl_seconds=30,
)

# Use cases.
#
# itq_courses is a Mode B (consuming) service — the ACL tables are
# owned by itq_users (the source-of-truth). We read user rows through
# ResolveUserFromJwtUseCase; a missing user means itq_users hasn't
# provisioned them yet, which pkg_auth maps to HTTP 403. Mode A services
# use SyncUserFromJwtUseCase instead (see docs/FastAPI.md).
resolve_user_use_case = ResolveUserFromJwtUseCase(user_repo=user_repo)
resolve_use_case = ResolveAuthContextUseCase(membership_repo=membership_repo)
register_catalog_use_case = RegisterPermissionCatalogUseCase(catalog_repo=catalog_repo)

# Composed FastAPI dependency: returns (IdentityContext, AuthContext)
get_auth_context = make_get_auth_context(
    get_identity=get_identity,
    resolve_user_use_case=resolve_user_use_case,
    resolve_use_case=resolve_use_case,
    organization_repo=organization_repo,
)


def configure_app(app):
    """Install pkg_auth exception handlers on the FastAPI app."""
    install_exception_handlers(app)


__all__ = [
    "get_identity",
    "get_auth_context",
    "require_permission",
    "register_catalog_use_case",
    "configure_app",
    "user_repo",
    "organization_repo",
    "role_repo",
    "catalog_repo",
    "membership_repo",
]
