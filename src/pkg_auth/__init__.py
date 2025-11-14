"""
pkg_auth

Clean-architecture authentication core that can be integrated with
multiple frameworks (FastAPI, Django, etc.).
"""

__version__ = "0.1.0"

from .domain.entities import AccessContext, IdentityInfo, SessionInfo, AccessRights
from .domain.constants import ClaimSet
from .domain.exceptions import (
    TokenExpiredError,
    InvalidTokenError,
    AuthenticationError,
    AuthorizationError,
)
from .domain.value_objects import (
    Subject,
    EmailAddress,
    RealmName,
    AccessRequirement,
)
from .domain.ports import TokenDecoder

from .application.use_cases.authenticate import AuthenticateTokenUseCase
from .application.use_cases.authorize import AuthorizeAccessUseCase

# Keycloak-specific adapter (optional to re-export)
from .adapters.keycloak.jwt_decoder import JWTTokenDecoder

__all__ = [
    "__version__",
    # domain core
    "AccessContext",
    "IdentityInfo",
    "SessionInfo",
    "AccessRights",
    "ClaimSet",
    "Subject",
    "EmailAddress",
    "RealmName",
    "AccessRequirement",
    "TokenDecoder",
    # exceptions
    "TokenExpiredError",
    "InvalidTokenError",
    "AuthenticationError",
    "AuthorizationError",
    # use cases
    "AuthenticateTokenUseCase",
    "AuthorizeAccessUseCase",
    # adapters
    "JWTTokenDecoder",
]
