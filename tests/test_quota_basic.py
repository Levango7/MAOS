"""Basic functional tests for ``QuotaManager`` (``maop.enterprise.quota``).

Covers quota CRUD, usage tracking, and the check_quota decision logic
(soft-limit warning, hard-limit rejection, fail-open).  All tests run
with ENTERPRISE edition activated and an isolated SQLite DB via ``tmp_path``.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def quota(enterprise_edition, tmp_path: Path):
    """A ``QuotaManager`` backed by a temporary SQLite database."""
    from maop.enterprise.quota import QuotaManager

    db_path = tmp_path / "test_quota.db"
    return QuotaManager(db_path)


# ── set / get quota ─────────────────────────────────────────────────

def test_set_quota_returns_response(quota):
    resp = quota.set_quota("tenant1", "api_calls", hard_limit=1000)
    assert resp.tenant_id == "tenant1"
    assert resp.resource == "api_calls"
    assert resp.hard_limit == 1000


def test_get_quota_after_set(quota):
    quota.set_quota("tenant1", "api_calls", hard_limit=1000)
    resp = quota.get_quota("tenant1", "api_calls")
    assert resp is not None
    assert resp.hard_limit == 1000


def test_get_quota_nonexistent_returns_none(quota):
    assert quota.get_quota("ghost", "api_calls") is None


def test_set_quota_with_soft_limit(quota):
    resp = quota.set_quota("tenant1", "api_calls", hard_limit=1000, soft_limit=800)
    assert resp.soft_limit == 800


def test_set_quota_soft_limit_capped_at_hard(quota):
    """soft_limit > hard_limit is auto-corrected to hard_limit."""
    resp = quota.set_quota("tenant1", "api_calls", hard_limit=100, soft_limit=200)
    assert resp.soft_limit == 100


def test_set_quota_invalid_period(quota):
    with pytest.raises(ValueError):
        quota.set_quota("tenant1", "api_calls", hard_limit=100, period="weekly")


def test_set_quota_negative_hard_limit(quota):
    with pytest.raises(ValueError):
        quota.set_quota("tenant1", "api_calls", hard_limit=-1)


# ── list / delete ───────────────────────────────────────────────────

def test_list_quotas_empty(quota):
    assert quota.list_quotas("tenant1") == []


def test_list_quotas_after_set(quota):
    quota.set_quota("tenant1", "api_calls", hard_limit=1000)
    quota.set_quota("tenant1", "storage_mb", hard_limit=5000)
    quotas = quota.list_quotas("tenant1")
    assert len(quotas) == 2


def test_delete_quota(quota):
    quota.set_quota("tenant1", "api_calls", hard_limit=1000)
    assert quota.delete_quota("tenant1", "api_calls")
    assert quota.get_quota("tenant1", "api_calls") is None


def test_delete_quota_nonexistent_returns_false(quota):
    assert not quota.delete_quota("ghost", "api_calls")


# ── usage tracking ──────────────────────────────────────────────────

def test_update_usage(quota):
    used = quota.update_usage("tenant1", "api_calls", 10)
    assert used == 10


def test_update_usage_accumulates(quota):
    quota.update_usage("tenant1", "api_calls", 10)
    used = quota.update_usage("tenant1", "api_calls", 5)
    assert used == 15


def test_get_usage_default(quota):
    usage = quota.get_usage("tenant1", "api_calls")
    assert usage.used == 0


# ── check_quota ─────────────────────────────────────────────────────

def test_check_quota_allowed_within_limit(quota):
    quota.set_quota("tenant1", "api_calls", hard_limit=1000)
    result = quota.check_quota("tenant1", "api_calls", amount=1)
    assert result.allowed


def test_check_quota_rejected_over_hard_limit(quota):
    quota.set_quota("tenant1", "api_calls", hard_limit=10)
    quota.update_usage("tenant1", "api_calls", 10)
    result = quota.check_quota("tenant1", "api_calls", amount=1)
    assert not result.allowed
    assert result.reason


def test_check_quota_fail_open_no_quota_set(quota):
    """No quota configured → fail-open (allowed)."""
    result = quota.check_quota("tenant1", "api_calls", amount=1)
    assert result.allowed


def test_check_quota_soft_limit_warning(quota):
    """Exceeding soft limit is allowed but emits a warning."""
    quota.set_quota("tenant1", "api_calls", hard_limit=100, soft_limit=50)
    quota.update_usage("tenant1", "api_calls", 50)
    result = quota.check_quota("tenant1", "api_calls", amount=1)
    assert result.allowed
    assert result.warning  # soft-limit breach recorded


def test_check_quota_zero_hard_limit_means_unlimited(quota):
    """hard_limit=0 means unlimited → always allowed."""
    quota.set_quota("tenant1", "api_calls", hard_limit=0)
    result = quota.check_quota("tenant1", "api_calls", amount=999999)
    assert result.allowed