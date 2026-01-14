from dataclasses import dataclass, field
from typing import Optional, Set, Iterable

from .constants import ClaimSet
from .value_objects import EmailAddress, Subject, RealmName


@dataclass(slots=True)
class IdentityInfo:
    """
    Identity-related information about the authenticated principal.
    Purely based on OIDC / Keycloak token claims.
    """
    subject: Subject | None = None
    email: EmailAddress | None = None
    email_verified: bool = False

    full_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    preferred_username: Optional[str] = None


@dataclass(slots=True)
class SessionInfo:
    """
    Session and token metadata.
    """
    session_id: Optional[str] = None
    issued_at: Optional[int] = None
    expires_at: Optional[int] = None
    auth_time: Optional[int] = None
    realm: RealmName | None = None


@dataclass(slots=True)
class AccessRights:
    """
    Roles, scopes, audiences and roles-as-permissions from Keycloak.
    This package does NOT interpret their business meaning.
    """
    # OIDC / OAuth
    scopes: Set[str] = field(default_factory=set)
    audiences: Set[str] = field(default_factory=set)

    # Role-based access
    realm_roles: Set[str] = field(default_factory=set)
    client_roles: Set[str] = field(default_factory=set)

    # Uninterpreted "permissions" (e.g. union of all client roles or your own choice)
    permissions: Set[str] = field(default_factory=set)

    # ---- internal helper -------------------------------------------------

    def _get_set(self, target: ClaimSet) -> Set[str]:
        if target is ClaimSet.REALM_ROLE:
            return self.realm_roles
        if target is ClaimSet.CLIENT_ROLE:
            return self.client_roles
        if target is ClaimSet.PERMISSION:
            return self.permissions
        if target is ClaimSet.SCOPE:
            return self.scopes
        if target is ClaimSet.AUDIENCE:
            return self.audiences
        # Fallback – should not happen
        return set()

    # ---- generic public helpers ------------------------------------------

    def contains(self, value: str, target: ClaimSet) -> bool:
        return value in self._get_set(target)

    def contains_any(self, values: Iterable[str], target: ClaimSet) -> bool:
        s = self._get_set(target)
        return any(v in s for v in values)

    def contains_all(self, values: Iterable[str], target: ClaimSet) -> bool:
        s = self._get_set(target)
        return all(v in s for v in values)


@dataclass(slots=True)
class AccessContext:
    """
    Aggregate that bundles identity, session information and access rights.
    """
    identity: IdentityInfo = field(default_factory=IdentityInfo)
    session: SessionInfo = field(default_factory=SessionInfo)
    rights: AccessRights = field(default_factory=AccessRights)

    # --- Read-only shortcuts for common identity/session fields -----------

    @property
    def email(self) -> Optional[str]:
        return str(self.identity.email) if self.identity.email else None

    @property
    def subject(self) -> Optional[str]:
        return str(self.identity.subject) if self.identity.subject else None

    @property
    def full_name(self) -> Optional[str]:
        return self.identity.full_name

    @property
    def preferred_username(self) -> Optional[str]:
        return self.identity.preferred_username

    @property
    def session_id(self) -> Optional[str]:
        return self.session.session_id

    @property
    def realm(self) -> Optional[str]:
        return str(self.session.realm) if self.session.realm else None
