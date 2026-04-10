"""Seed an org / role / membership for local development.

Run after applying the pkg_auth ACL migrations against your DB:

    python -m courses_app.seed

This is intentionally minimal — no error handling, no idempotency
beyond what the use cases provide. Production seeding belongs in the
users service, not here.
"""
from __future__ import annotations

import asyncio
import os

from pkg_auth.authorization import PermissionKey, RoleName
from pkg_auth.authorization.application.use_cases.create_organization import (
    CreateOrganizationUseCase,
)
from pkg_auth.authorization.application.use_cases.create_role import (
    CreateRoleUseCase,
)
from pkg_auth.authorization.application.use_cases.upsert_membership import (
    UpsertMembershipUseCase,
)

from .deps import (
    catalog_repo,
    membership_repo,
    organization_repo,
    register_catalog_use_case,
    role_repo,
    user_repo,
)
from .permissions import CATALOG, SERVICE_NAME


async def main() -> None:
    # 1. Register this service's catalog (so role creation can validate keys)
    await register_catalog_use_case.execute(
        service_name=SERVICE_NAME,
        entries=[(k, d) for k, d in CATALOG],
    )

    # 2. Create the local user from a Keycloak sub. In real life this
    #    happens lazily on first request, but for seeding we do it
    #    explicitly.
    sub = os.environ.get("SEED_USER_SUB", "kc-uuid-local-dev")
    email = os.environ.get("SEED_USER_EMAIL", "dev@example.com")
    user = await user_repo.upsert_from_identity(
        sub=sub, email=email, full_name="Local Dev",
    )

    # 3. Create an org
    create_org = CreateOrganizationUseCase(organization_repo=organization_repo)
    org = await create_org.execute(slug="acme", name="ACME Corp")

    # 4. Create an editor role with a couple of perms
    create_role = CreateRoleUseCase(
        organization_repo=organization_repo,
        role_repo=role_repo,
        catalog_repo=catalog_repo,
    )
    role = await create_role.execute(
        org_id=org.id,
        name=RoleName("editor"),
        description="Course editor",
        permission_keys=[
            PermissionKey("course:view"),
            PermissionKey("course:edit"),
            PermissionKey("course:publish"),
        ],
    )

    # 5. Grant the user the editor role in this org
    upsert = UpsertMembershipUseCase(
        user_repo=user_repo,
        organization_repo=organization_repo,
        role_repo=role_repo,
        membership_repo=membership_repo,
    )
    await upsert.execute(user_id=user.id, org_id=org.id, role_id=role.id)

    print(f"Seeded: user={user.id} org={org.id} role={role.id} (slug=acme)")
    print("Hit the API with:")
    print("  X-Organization-Id: acme")
    print(f"  Authorization: Bearer <JWT for sub={sub}>")


if __name__ == "__main__":
    asyncio.run(main())
