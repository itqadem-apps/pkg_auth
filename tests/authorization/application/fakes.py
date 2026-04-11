from uuid import UUID, uuid4
"""In-memory fake repositories for application-layer unit tests.

Each fake implements its corresponding Protocol with a dict-backed
store. No I/O, no async overhead beyond ``async def``. The same fakes
are reused across many test files via the conftest fixtures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from pkg_auth.authorization import (
    AuthContext,
    Membership,
    Organization,
    Permission,
    Role,
    User,
)
from pkg_auth.authorization import (
    OrgId,
    PermissionId,
    PermissionKey,
    RoleId,
    RoleName,
    UserId,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# UserRepository
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FakeUserRepository:
    _by_id: dict[int, User] = field(default_factory=dict)
    _by_sub: dict[str, User] = field(default_factory=dict)
    _next_id: int = 1  # unused but kept for compat

    async def get_by_id(self, user_id: UserId) -> User | None:
        return self._by_id.get(user_id.value)

    async def get_by_keycloak_sub(self, sub: str) -> User | None:
        return self._by_sub.get(sub)

    async def upsert_from_identity(
        self,
        *,
        sub: str,
        email: str,
        full_name: str | None,
    ) -> User:
        existing = self._by_sub.get(sub)
        now = _utcnow()
        if existing is not None:
            updated = User(
                id=existing.id,
                keycloak_sub=existing.keycloak_sub,
                email=email,
                full_name=full_name,
                first_seen_at=existing.first_seen_at,
                last_seen_at=now,
            )
            self._by_id[existing.id.value] = updated
            self._by_sub[sub] = updated
            return updated
        new_id = uuid4()  # generate UUID
        # self._next_id += 1
        user = User(
            id=UserId(uuid4()),
            keycloak_sub=sub,
            email=email,
            full_name=full_name,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._by_id[new_id] = user
        self._by_sub[sub] = user
        return user


# --------------------------------------------------------------------------- #
# OrganizationRepository
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FakeOrganizationRepository:
    _by_id: dict[int, Organization] = field(default_factory=dict)
    _by_slug: dict[str, int] = field(default_factory=dict)
    _user_to_orgs: dict[int, set[int]] = field(default_factory=dict)
    _next_id: int = 1  # unused but kept for compat

    async def get(self, org_id: OrgId) -> Organization | None:
        return self._by_id.get(org_id.value)

    async def get_by_slug(self, slug: str) -> Organization | None:
        oid = self._by_slug.get(slug)
        return self._by_id.get(oid) if oid is not None else None

    async def create(self, *, slug: str, name: str) -> Organization:
        if slug in self._by_slug:
            raise ValueError(f"slug already exists: {slug!r}")
        new_id = uuid4()  # generate UUID
        # self._next_id += 1
        org = Organization(
            id=OrgId(uuid4()),
            slug=slug,
            name=name,
            created_at=_utcnow(),
        )
        self._by_id[new_id] = org
        self._by_slug[slug] = new_id
        return org

    async def update(
        self, org_id: OrgId, *, name: str | None
    ) -> Organization:
        existing = self._by_id.get(org_id.value)
        if existing is None:
            raise ValueError(f"org {org_id} not found")
        updated = Organization(
            id=existing.id,
            slug=existing.slug,
            name=name if name is not None else existing.name,
            created_at=existing.created_at,
        )
        self._by_id[existing.id.value] = updated
        return updated

    async def delete(self, org_id: OrgId) -> None:
        existing = self._by_id.pop(org_id.value, None)
        if existing is not None:
            self._by_slug.pop(existing.slug, None)
            for orgs in self._user_to_orgs.values():
                orgs.discard(org_id.value)

    async def list_for_user(self, user_id: UserId) -> list[Organization]:
        org_ids = self._user_to_orgs.get(user_id.value, set())
        return [
            self._by_id[oid] for oid in sorted(org_ids) if oid in self._by_id
        ]

    # ----- test helper (not part of Protocol) -------------------------- #
    def _link(self, user_id: UserId, org_id: OrgId) -> None:
        self._user_to_orgs.setdefault(user_id.value, set()).add(org_id.value)


# --------------------------------------------------------------------------- #
# RoleRepository
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FakeRoleRepository:
    _by_id: dict[int, Role] = field(default_factory=dict)
    _by_org_name: dict[tuple[int | None, str], int] = field(default_factory=dict)
    _next_id: int = 1  # unused but kept for compat

    async def get(self, role_id: RoleId) -> Role | None:
        return self._by_id.get(role_id.value)

    async def get_by_name(
        self, org_id: OrgId | None, name: RoleName
    ) -> Role | None:
        key = (org_id.value if org_id is not None else None, str(name))
        rid = self._by_org_name.get(key)
        return self._by_id.get(rid) if rid is not None else None

    async def create(
        self,
        *,
        org_id: OrgId | None,
        name: RoleName,
        description: str | None,
        permission_keys: Sequence[PermissionKey],
    ) -> Role:
        key = (org_id.value if org_id is not None else None, str(name))
        if key in self._by_org_name:
            raise ValueError(f"role already exists: {key}")
        new_id = uuid4()  # generate UUID
        # self._next_id += 1
        role = Role(
            id=RoleId(uuid4()),
            organization_id=org_id,
            name=name,
            description=description,
            permission_keys=frozenset(str(k) for k in permission_keys),
        )
        self._by_id[new_id] = role
        self._by_org_name[key] = new_id
        return role

    async def update(
        self,
        role_id: RoleId,
        *,
        name: RoleName | None,
        description: str | None,
        permission_keys: Sequence[PermissionKey] | None,
    ) -> Role:
        existing = self._by_id.get(role_id.value)
        if existing is None:
            raise ValueError(f"role {role_id} not found")
        new_name = name if name is not None else existing.name
        new_perms = (
            frozenset(str(k) for k in permission_keys)
            if permission_keys is not None
            else existing.permission_keys
        )
        updated = Role(
            id=existing.id,
            organization_id=existing.organization_id,
            name=new_name,
            description=description if description is not None else existing.description,
            permission_keys=new_perms,
        )
        self._by_id[existing.id.value] = updated
        if name is not None and str(name) != str(existing.name):
            old_key = (
                int(existing.organization_id)
                if existing.organization_id is not None
                else None,
                str(existing.name),
            )
            new_key = (
                int(existing.organization_id)
                if existing.organization_id is not None
                else None,
                str(new_name),
            )
            self._by_org_name.pop(old_key, None)
            self._by_org_name[new_key] = existing.id.value
        return updated

    async def delete(self, role_id: RoleId) -> None:
        existing = self._by_id.pop(role_id.value, None)
        if existing is not None:
            key = (
                int(existing.organization_id)
                if existing.organization_id is not None
                else None,
                str(existing.name),
            )
            self._by_org_name.pop(key, None)


# --------------------------------------------------------------------------- #
# MembershipRepository
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FakeMembershipRepository:
    """Fake membership repo. Wire ``role_repo`` so it can build AuthContexts.

    The denormalization of role name + perms onto AuthContext is done
    via the linked role repo, simulating what the SQLAlchemy impl will
    do via a JOIN.
    """

    role_repo: "FakeRoleRepository | None" = None
    _by_user_org: dict[tuple[int, int], Membership] = field(default_factory=dict)
    _next_id: int = 1  # unused but kept for compat

    async def get(
        self, user_id: UserId, org_id: OrgId
    ) -> Membership | None:
        return self._by_user_org.get((user_id.value, org_id.value))

    async def upsert(
        self,
        *,
        user_id: UserId,
        org_id: OrgId,
        role_id: RoleId,
        status: str,
    ) -> Membership:
        if self.role_repo is None:
            raise RuntimeError(
                "FakeMembershipRepository.role_repo must be wired for upsert"
            )
        role = await self.role_repo.get(role_id)
        if role is None:
            raise ValueError(f"role {role_id} not found")
        key = (user_id.value, org_id.value)
        existing = self._by_user_org.get(key)
        if existing is not None:
            updated = Membership(
                id=existing.id,
                user_id=user_id,
                organization_id=org_id,
                role_id=role_id,
                role_name=role.name,
                status=status,
                joined_at=existing.joined_at,
            )
        else:
            new_id = uuid4()  # generate UUID
            # self._next_id += 1
            updated = Membership(
                id=new_id,
                user_id=user_id,
                organization_id=org_id,
                role_id=role_id,
                role_name=role.name,
                status=status,
                joined_at=_utcnow(),
            )
        self._by_user_org[key] = updated
        return updated

    async def delete(self, user_id: UserId, org_id: OrgId) -> None:
        self._by_user_org.pop((user_id.value, org_id.value), None)

    async def load_auth_context(
        self, user_id: UserId, org_id: OrgId
    ) -> AuthContext | None:
        membership = self._by_user_org.get((user_id.value, org_id.value))
        if membership is None or self.role_repo is None:
            return None
        if membership.status != "active":
            return None
        role = await self.role_repo.get(membership.role_id)
        if role is None:
            return None
        return AuthContext(
            user_id=user_id,
            organization_id=org_id,
            role_name=role.name,
            perms=role.permission_keys,
        )

    async def list_for_user(self, user_id: UserId) -> list[Membership]:
        return [
            m for (uid, _), m in self._by_user_org.items() if uid == user_id.value
        ]


# --------------------------------------------------------------------------- #
# PermissionCatalogRepository
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FakePermissionCatalogRepository:
    _by_id: dict[int, Permission] = field(default_factory=dict)
    _by_key: dict[str, int] = field(default_factory=dict)
    _next_id: int = 1  # unused but kept for compat

    async def register_many(
        self,
        *,
        service_name: str,
        entries: Sequence[tuple[PermissionKey, str | None]],
    ) -> None:
        for key, description in entries:
            existing_id = self._by_key.get(str(key))
            if existing_id is not None:
                old = self._by_id[existing_id]
                self._by_id[existing_id] = Permission(
                    id=old.id,
                    key=key,
                    service_name=service_name,
                    description=description,
                )
            else:
                new_id = uuid4()  # generate UUID
                # self._next_id += 1
                perm = Permission(
                    id=PermissionId(uuid4()),
                    key=key,
                    service_name=service_name,
                    description=description,
                )
                self._by_id[new_id] = perm
                self._by_key[str(key)] = new_id

    async def list_all(self) -> list[Permission]:
        return list(self._by_id.values())

    async def list_for_service(self, service_name: str) -> list[Permission]:
        return [
            p for p in self._by_id.values() if p.service_name == service_name
        ]
