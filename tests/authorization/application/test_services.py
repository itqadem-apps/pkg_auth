"""Tests for the service registry + entitlement use cases."""
from uuid import uuid4

import pytest

from pkg_auth.authorization import (
    OrgId,
    ServiceName,
    ServiceNotSaaSAvailable,
    ServiceSpec,
    UnknownService,
)
from pkg_auth.authorization.application.use_cases.provision_default_services import (
    ProvisionDefaultServicesUseCase,
)
from pkg_auth.authorization.application.use_cases.set_organization_service import (
    SetOrganizationServiceUseCase,
)
from pkg_auth.authorization.application.use_cases.sync_service_catalog import (
    SyncServiceCatalogUseCase,
)

from .fakes import FakeOrganizationServiceRepository, FakeServiceRepository


# --------------------------------------------------------------------------- #
# SyncServiceCatalogUseCase
# --------------------------------------------------------------------------- #


async def test_sync_services_upserts_and_prunes():
    repo = FakeServiceRepository()
    await repo.upsert_many([ServiceSpec.make("legacy")])

    uc = SyncServiceCatalogUseCase(service_repo=repo)
    result = await uc.execute(
        services=[
            ServiceSpec.make("users", {"en": "Users"}, auto_provision=True),
            ServiceSpec.make("assessments", saas_available=True),
        ]
    )
    assert result.upserted == 2
    assert result.pruned == 1
    names = sorted(str(s.name) for s in await repo.list_all())
    assert names == ["assessments", "users"]


async def test_sync_services_dry_run_does_not_write():
    repo = FakeServiceRepository()
    await repo.upsert_many([ServiceSpec.make("legacy")])
    uc = SyncServiceCatalogUseCase(service_repo=repo)
    result = await uc.execute(
        services=[ServiceSpec.make("users")], dry_run=True
    )
    assert result.pruned == 1 and result.dry_run is True
    assert [str(s.name) for s in await repo.list_all()] == ["legacy"]


# --------------------------------------------------------------------------- #
# ProvisionDefaultServicesUseCase
# --------------------------------------------------------------------------- #


async def test_provision_enables_only_auto_provision_services():
    services = FakeServiceRepository()
    await services.upsert_many(
        [
            ServiceSpec.make("users", auto_provision=True),
            ServiceSpec.make("courses", auto_provision=True),
            ServiceSpec.make("assessments", auto_provision=False),
        ]
    )
    org_services = FakeOrganizationServiceRepository()
    org_id = OrgId(uuid4())

    uc = ProvisionDefaultServicesUseCase(
        service_repo=services, org_service_repo=org_services
    )
    granted = await uc.execute(org_id=org_id)

    assert sorted(granted) == ["courses", "users"]
    assert await org_services.list_enabled_service_names(org_id) == {
        "courses",
        "users",
    }


# --------------------------------------------------------------------------- #
# SetOrganizationServiceUseCase (SaaS governance)
# --------------------------------------------------------------------------- #


async def test_enable_rejected_when_not_saas_available():
    services = FakeServiceRepository()
    await services.upsert_many([ServiceSpec.make("courses", saas_available=False)])
    org_services = FakeOrganizationServiceRepository()
    uc = SetOrganizationServiceUseCase(
        service_repo=services, org_service_repo=org_services
    )
    with pytest.raises(ServiceNotSaaSAvailable):
        await uc.execute(
            org_id=OrgId(uuid4()),
            service_name=ServiceName("courses"),
            enabled=True,
        )


async def test_enable_allowed_when_saas_available():
    services = FakeServiceRepository()
    await services.upsert_many([ServiceSpec.make("courses", saas_available=True)])
    org_services = FakeOrganizationServiceRepository()
    org_id = OrgId(uuid4())
    uc = SetOrganizationServiceUseCase(
        service_repo=services, org_service_repo=org_services
    )
    ent = await uc.execute(
        org_id=org_id, service_name=ServiceName("courses"), enabled=True
    )
    assert ent is not None and ent.enabled and ent.source == "manual"
    assert await org_services.list_enabled_service_names(org_id) == {"courses"}


async def test_disable_always_allowed_even_if_not_saas():
    services = FakeServiceRepository()
    await services.upsert_many([ServiceSpec.make("courses", saas_available=False)])
    org_services = FakeOrganizationServiceRepository()
    org_id = OrgId(uuid4())
    await org_services.enable(org_id, ServiceName("courses"), source="auto")

    uc = SetOrganizationServiceUseCase(
        service_repo=services, org_service_repo=org_services
    )
    await uc.execute(
        org_id=org_id, service_name=ServiceName("courses"), enabled=False
    )
    assert await org_services.list_enabled_service_names(org_id) == set()


async def test_unknown_service_raises():
    services = FakeServiceRepository()
    org_services = FakeOrganizationServiceRepository()
    uc = SetOrganizationServiceUseCase(
        service_repo=services, org_service_repo=org_services
    )
    with pytest.raises(UnknownService):
        await uc.execute(
            org_id=OrgId(uuid4()),
            service_name=ServiceName("ghost"),
            enabled=True,
        )
