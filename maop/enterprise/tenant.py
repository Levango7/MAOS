"""MAOP Enterprise Multi-Tenant Isolation.

Extends core/tenant.py with full tenant lifecycle management,
resource quotas, data isolation, and billing integration.

Each tenant gets:
  - Isolated namespace (data, config, agents)
  - Resource quotas (API calls, storage, compute)
  - Separate audit trail
  - Billing/cost tracking
"""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    TERMINATED = "terminated"


class TenantQuota(BaseModel):
    max_api_calls_per_day: int = 10000
    max_storage_mb: int = 5120
    max_agents: int = 50
    max_concurrent_tasks: int = 10
    max_users: int = 20


class Tenant(BaseModel):
    tenant_id: str
    name: str
    status: TenantStatus = TenantStatus.TRIAL
    plan: str = "starter"
    quota: TenantQuota = Field(default_factory=TenantQuota)
    created_at: float = 0.0
    updated_at: float = 0.0
    expires_at: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TenantUsage(BaseModel):
    api_calls_today: int = 0
    storage_mb: float = 0.0
    active_agents: int = 0
    concurrent_tasks: int = 0
    active_users: int = 0


#: update_tenant 允许修改的字段（P1 #23）。tenant_id/created_at/updated_at
#: 是身份与审计字段，禁止通过 update_tenant 覆写。
_UPDATABLE_TENANT_FIELDS: frozenset[str] = frozenset(
    {"name", "status", "plan", "quota", "expires_at", "metadata"}
)


class TenantManager:
    """Enterprise multi-tenant lifecycle manager with optional PG persistence."""

    def __init__(self) -> None:
        require_feature(FeatureFlag.TENANT_ISOLATION)
        self._tenants: dict[str, Tenant] = {}
        self._usage: dict[str, TenantUsage] = {}
        self._pg: PgTenantStore | None = None
        try:
            from maop.enterprise.pg_persist import PgTenantStore
            pg = PgTenantStore()
            if pg.available:
                self._pg = pg
                self._load_from_pg()
        except Exception as e:
            logger.debug("ignored: %s", e, exc_info=True)

    def _load_from_pg(self) -> None:
        if not self._pg:
            return
        for row in self._pg.load_tenants():
            quota_data = row.get("quota", {})
            if isinstance(quota_data, str):
                import json
                quota_data = json.loads(quota_data)
            meta_data = row.get("metadata", {})
            if isinstance(meta_data, str):
                import json
                meta_data = json.loads(meta_data)
            self._tenants[row["tenant_id"]] = Tenant(
                tenant_id=row["tenant_id"], name=row.get("name", ""),
                status=TenantStatus(row.get("status", "trial")),
                plan=row.get("plan", "starter"),
                quota=TenantQuota(**quota_data) if quota_data else TenantQuota(),
                created_at=row.get("created_at", 0.0),
                updated_at=row.get("updated_at", 0.0),
                expires_at=row.get("expires_at"),
                metadata=meta_data,
            )
            usage_row = self._pg.load_usage(row["tenant_id"])
            if usage_row:
                self._usage[row["tenant_id"]] = TenantUsage(
                    api_calls_today=usage_row.get("api_calls_today", 0),
                    storage_mb=usage_row.get("storage_mb", 0.0),
                    active_agents=usage_row.get("active_agents", 0),
                    concurrent_tasks=usage_row.get("concurrent_tasks", 0),
                    active_users=usage_row.get("active_users", 0),
                )

    def create_tenant(self, tenant_id: str, name: str, *, plan: str = "starter", quota: TenantQuota | None = None) -> Tenant:
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' already exists")
        now = time.time()
        tenant = Tenant(
            tenant_id=tenant_id, name=name, plan=plan,
            quota=quota or TenantQuota(), created_at=now, updated_at=now,
        )
        self._tenants[tenant_id] = tenant
        self._usage[tenant_id] = TenantUsage()
        if self._pg:
            self._pg.save_tenant(tenant.model_dump())
            self._pg.save_usage(tenant_id, {})
        logger.info("[tenant] Created tenant=%s name=%s plan=%s", tenant_id, name, plan)
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def update_tenant(self, tenant_id: str, **kwargs: Any) -> Tenant:
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            raise KeyError(f"Tenant '{tenant_id}' not found")
        # P1 #23 fix: 字段白名单 —— 旧实现 hasattr/setattr 允许覆写
        # tenant_id/created_at 等身份与审计字段（调用方传什么改什么）。
        # 类型校验（P0 修复）：status 必须是合法枚举、quota 必须是
        # TenantQuota（dict 自动转换），否则直接拒绝 —— 旧实现可把
        # status 设为任意字符串、quota 设为 dict，导致后续访问
        # tenant.quota.max_* 抛 AttributeError。
        for k, v in kwargs.items():
            if k not in _UPDATABLE_TENANT_FIELDS:
                logger.warning(
                    "[tenant] update_tenant: ignoring non-updatable field %r", k
                )
                continue
            if k == "status":
                if v is None:
                    continue
                if isinstance(v, TenantStatus):
                    tenant.status = v
                elif isinstance(v, str) and v in TenantStatus._value2member_map_:
                    tenant.status = TenantStatus(v)
                else:
                    raise ValueError(
                        f"Invalid tenant status: {v!r} "
                        f"(expected one of {[s.value for s in TenantStatus]})"
                    )
            elif k == "quota":
                if v is None:
                    continue
                if isinstance(v, TenantQuota):
                    tenant.quota = v
                elif isinstance(v, dict):
                    tenant.quota = TenantQuota(**v)
                else:
                    raise TypeError(
                        f"tenant.quota must be TenantQuota or dict, got {type(v).__name__}"
                    )
            else:
                setattr(tenant, k, v)
        tenant.updated_at = time.time()
        if self._pg:
            self._pg.save_tenant(tenant.model_dump())
        return tenant

    def suspend_tenant(self, tenant_id: str) -> bool:
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = TenantStatus.SUSPENDED
        tenant.updated_at = time.time()
        if self._pg:
            self._pg.save_tenant(tenant.model_dump())
        logger.warning("[tenant] Suspended tenant=%s", tenant_id)
        return True

    def activate_tenant(self, tenant_id: str) -> bool:
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        tenant.status = TenantStatus.ACTIVE
        tenant.updated_at = time.time()
        if self._pg:
            self._pg.save_tenant(tenant.model_dump())
        logger.info("[tenant] Activated tenant=%s", tenant_id)
        return True

    def delete_tenant(self, tenant_id: str) -> bool:
        if tenant_id not in self._tenants:
            return False
        del self._tenants[tenant_id]
        self._usage.pop(tenant_id, None)
        if self._pg:
            self._pg.delete_tenant(tenant_id)
        logger.info("[tenant] Deleted tenant=%s", tenant_id)
        return True

    def check_quota(self, tenant_id: str, resource: str, current: int) -> bool:
        tenant = self._tenants.get(tenant_id)
        if not tenant:
            return False
        quota_map = {
            "api_calls": tenant.quota.max_api_calls_per_day,
            "storage_mb": tenant.quota.max_storage_mb,
            "agents": tenant.quota.max_agents,
            "concurrent_tasks": tenant.quota.max_concurrent_tasks,
            "users": tenant.quota.max_users,
        }
        if resource not in quota_map:
            # P0 修复: 未知资源 fail-closed（记录告警并拒绝）。
            # 旧实现 ``quota_map.get(resource, 0)`` → limit=0 → 恒放行,
            # 调用方拼错资源名（如 "api_call"）即永久绕过配额。
            logger.error(
                "[tenant] check_quota: unknown resource %r for tenant=%s — "
                "denying (fail-closed). Known resources: %s",
                resource, tenant_id, sorted(quota_map),
            )
            return False
        limit = quota_map[resource]
        return current < limit if limit > 0 else True

    def get_usage(self, tenant_id: str) -> TenantUsage:
        return self._usage.get(tenant_id, TenantUsage())

    def list_tenants(self, status: TenantStatus | None = None) -> list[Tenant]:
        tenants = list(self._tenants.values())
        if status:
            tenants = [t for t in tenants if t.status == status]
        return tenants
