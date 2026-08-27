"""Basic functional tests for ``TenantManager`` (``maop.enterprise.tenant``).

Covers tenant lifecycle (create → get → suspend → activate → delete),
quota checking, and usage tracking.  All tests run with ENTERPRISE edition
activated via the ``enterprise_edition`` fixture.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def tenant_mgr(enterprise_edition):
    """A fresh ``TenantManager`` instance (no PG persistence in tests)."""
    from maop.enterprise.tenant import TenantManager

    return TenantManager()


# ── Tenant status enum ──────────────────────────────────────────────

def test_tenant_status_enum():
    from maop.enterprise.tenant import TenantStatus

    assert TenantStatus.ACTIVE.value == "active"
    assert TenantStatus.SUSPENDED.value == "suspended"
    assert TenantStatus.TRIAL.value == "trial"
    assert TenantStatus.TERMINATED.value == "terminated"


# ── Create / get ────────────────────────────────────────────────────

def test_create_tenant(tenant_mgr):
    tenant = tenant_mgr.create_tenant("t1", "Acme Corp")
    assert tenant.tenant_id == "t1"
    assert tenant.name == "Acme Corp"
    assert tenant.status.value == "trial"  # default status


def test_create_tenant_with_plan(tenant_mgr):
    tenant = tenant_mgr.create_tenant("t1", "Acme", plan="enterprise")
    assert tenant.plan == "enterprise"


def test_get_tenant(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    tenant = tenant_mgr.get_tenant("t1")
    assert tenant is not None
    assert tenant.name == "Acme"


def test_get_tenant_nonexistent(tenant_mgr):
    assert tenant_mgr.get_tenant("ghost") is None


def test_create_duplicate_tenant_raises(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    with pytest.raises(ValueError):
        tenant_mgr.create_tenant("t1", "Other")


# ── Update ──────────────────────────────────────────────────────────

def test_update_tenant(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    tenant = tenant_mgr.update_tenant("t1", name="Acme Renamed")
    assert tenant.name == "Acme Renamed"


def test_update_tenant_nonexistent_raises(tenant_mgr):
    with pytest.raises(KeyError):
        tenant_mgr.update_tenant("ghost", name="X")


# ── Suspend / activate ──────────────────────────────────────────────

def test_suspend_tenant(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    assert tenant_mgr.suspend_tenant("t1")
    tenant = tenant_mgr.get_tenant("t1")
    from maop.enterprise.tenant import TenantStatus
    assert tenant.status == TenantStatus.SUSPENDED


def test_activate_tenant(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    tenant_mgr.suspend_tenant("t1")
    assert tenant_mgr.activate_tenant("t1")
    tenant = tenant_mgr.get_tenant("t1")
    from maop.enterprise.tenant import TenantStatus
    assert tenant.status == TenantStatus.ACTIVE


def test_suspend_nonexistent_returns_false(tenant_mgr):
    assert not tenant_mgr.suspend_tenant("ghost")


def test_activate_nonexistent_returns_false(tenant_mgr):
    assert not tenant_mgr.activate_tenant("ghost")


# ── Delete ──────────────────────────────────────────────────────────

def test_delete_tenant(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    assert tenant_mgr.delete_tenant("t1")
    assert tenant_mgr.get_tenant("t1") is None


def test_delete_nonexistent_returns_false(tenant_mgr):
    assert not tenant_mgr.delete_tenant("ghost")


# ── List ────────────────────────────────────────────────────────────

def test_list_tenants_empty(tenant_mgr):
    assert tenant_mgr.list_tenants() == []


def test_list_tenants(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    tenant_mgr.create_tenant("t2", "Globex")
    tenants = tenant_mgr.list_tenants()
    assert len(tenants) == 2


def test_list_tenants_filtered_by_status(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    tenant_mgr.create_tenant("t2", "Globex")
    tenant_mgr.suspend_tenant("t2")
    from maop.enterprise.tenant import TenantStatus
    active = tenant_mgr.list_tenants(status=TenantStatus.SUSPENDED)
    assert len(active) == 1
    assert active[0].tenant_id == "t2"


# ── Quota ───────────────────────────────────────────────────────────

def test_check_quota_within_limit(tenant_mgr):
    from maop.enterprise.tenant import TenantQuota

    quota = TenantQuota(max_agents=10)
    tenant_mgr.create_tenant("t1", "Acme", quota=quota)
    assert tenant_mgr.check_quota("t1", "agents", 5)


def test_check_quota_exceeds_limit(tenant_mgr):
    from maop.enterprise.tenant import TenantQuota

    quota = TenantQuota(max_agents=10)
    tenant_mgr.create_tenant("t1", "Acme", quota=quota)
    assert not tenant_mgr.check_quota("t1", "agents", 10)  # current < limit, not <=


def test_check_quota_nonexistent_tenant(tenant_mgr):
    assert not tenant_mgr.check_quota("ghost", "agents", 1)


# ── Usage ───────────────────────────────────────────────────────────

def test_get_usage_default(tenant_mgr):
    tenant_mgr.create_tenant("t1", "Acme")
    usage = tenant_mgr.get_usage("t1")
    assert usage.api_calls_today == 0
    assert usage.active_agents == 0