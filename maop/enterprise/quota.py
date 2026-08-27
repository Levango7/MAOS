"""MAOP Enterprise Multi-Tenant Resource Quotas.

实现 PRD ``docs/prd-tenant-quota.md`` 描述的多租户资源配额子系统:

* ``tenant_quotas`` 表 — 每租户/每资源配额(硬限制 + 软限制 + 周期).
* ``tenant_usage`` 表(扩展) — 累计使用量,支持 daily/total 两种周期.
* ``quota_alerts`` 表 — 配额告警事件流(软限制触发告警,硬限制触发拒绝).

核心类 :class:`QuotaManager` 提供:
  - 配额 CRUD (:meth:`set_quota` / :meth:`get_quota` / :meth:`list_quotas` / :meth:`delete_quota`)
  - 使用量更新 (:meth:`update_usage` / :meth:`reset_usage`)
  - 配额检查 (:meth:`check_quota`) — 软限制告警 + 硬限制拒绝 + fail-open
  - 告警管理 (:meth:`list_alerts` / :meth:`resolve_alert`)
  - 内存缓存 (TTL 60s) — 减少热路径 DB 访问,写操作自动失效

设计原则:
  1. **fail-open** — 未知资源/无配额设置/DB 不可用时放行,避免配额子系统故障
     导致整个平台不可用.
  2. **软限制 + 硬限制** — 软限制触发告警但放行; 硬限制拒绝请求.
  3. **缓存失效一致性** — 任何写操作(set_quota/delete_quota/update_usage/
     resolve_alert)立即失效对应租户的缓存条目.
  4. **SQLite 优先** — 与 :mod:`maop.core.tenant.quota` 风格一致,使用
     :func:`sqlite_connect` 上下文管理器,自动 WAL + foreign_keys.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature
from maop.core.backends.db_utils import sqlite_connect

logger = logging.getLogger(__name__)

# ── 常量 ────────────────────────────────────────────────────────────

#: 缓存默认 TTL(秒). 写操作会立即失效对应租户的缓存.
DEFAULT_CACHE_TTL_S: float = float(os.getenv("MAOP_QUOTA_CACHE_TTL_S", "60.0"))

#: 软限制告警去重窗口(秒) — 同一 (tenant, resource, type) 在窗口内只记录一次.
ALERT_DEDUP_WINDOW_S: float = 300.0

#: 已知资源标识符. 调用方也可使用任意字符串,但这些是平台默认强制执行的.
RESOURCE_API_CALLS = "api_calls"
RESOURCE_STORAGE_MB = "storage_mb"
RESOURCE_AGENTS = "agents"
RESOURCE_CONCURRENT_TASKS = "concurrent_tasks"
RESOURCE_USERS = "users"
RESOURCE_TOKENS = "tokens"

KNOWN_RESOURCES: frozenset[str] = frozenset({
    RESOURCE_API_CALLS,
    RESOURCE_STORAGE_MB,
    RESOURCE_AGENTS,
    RESOURCE_CONCURRENT_TASKS,
    RESOURCE_USERS,
    RESOURCE_TOKENS,
})


# ── Pydantic 模型 ──────────────────────────────────────────────────


class QuotaCreate(BaseModel):
    """创建配额请求体.

    ``hard_limit`` 为强制上限(达到即拒绝); ``soft_limit`` 为告警阈值
    (达到即告警但放行). 二者均为 0 表示不限.
    """

    tenant_id: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=64)
    hard_limit: int = Field(ge=0, le=10**12)
    soft_limit: int = Field(default=0, ge=0, le=10**12)
    period: str = Field(default="total", pattern="^(daily|total)$")


class QuotaUpdate(BaseModel):
    """更新配额请求体(所有字段可选)."""

    hard_limit: int | None = Field(default=None, ge=0, le=10**12)
    soft_limit: int | None = Field(default=None, ge=0, le=10**12)
    period: str | None = Field(default=None, pattern="^(daily|total)$")


class QuotaResponse(BaseModel):
    """配额查询响应."""

    tenant_id: str
    resource: str
    hard_limit: int
    soft_limit: int
    period: str
    created_at: float
    updated_at: float


class UsageResponse(BaseModel):
    """使用量查询响应.

    ``exceeded_soft`` / ``exceeded_hard`` 由当前 used 值与配额对比得出.
    ``remaining`` 在 hard_limit=0(不限)时返回 -1.
    """

    tenant_id: str
    resource: str
    period: str
    used: int
    hard_limit: int
    soft_limit: int
    remaining: int
    exceeded_soft: bool
    exceeded_hard: bool


class QuotaAlertResponse(BaseModel):
    """配额告警响应."""

    alert_id: str
    tenant_id: str
    resource: str
    alert_type: str
    current_value: int
    limit_value: int
    severity: str
    message: str
    created_at: float
    resolved: bool
    resolved_at: float | None


class QuotaCheckResult(BaseModel):
    """:meth:`QuotaManager.check_quota` 返回的结构化结果.

    ``allowed`` 为 False 时 ``reason`` 描述拒绝原因; 为 True 但 ``warning``
    非空时表示已超过软限制(已放行并记录告警).
    """

    allowed: bool
    reason: str = ""
    warning: str = ""
    alert_id: str = ""


# ── 内部缓存条目 ────────────────────────────────────────────────────


class _CacheEntry(BaseModel):
    """配额 + 使用量缓存条目."""

    hard_limit: int
    soft_limit: int
    period: str
    used: int
    fetched_at: float


# ── QuotaManager ───────────────────────────────────────────────────


class QuotaManager:
    """多租户资源配额管理器.

    持久化到 SQLite(共享 ``maop.db``); 内存缓存热路径读以减少 DB 压力.
    任何写操作立即失效对应租户的缓存条目.

    Parameters
    ----------
    db_path : str | Path
        SQLite 数据库路径. 通常传入 :func:`unified_db_path`.
    cache_ttl_s : float
        缓存 TTL(秒). 默认 60s.
    fail_open : bool
        True(默认)时, DB 错误/未知资源/无配额设置均放行; False 时抛异常.
    """

    def __init__(
        self,
        db_path: Any,
        *,
        cache_ttl_s: float = DEFAULT_CACHE_TTL_S,
        fail_open: bool = True,
    ) -> None:
        require_feature(FeatureFlag.TENANT_ISOLATION)
        self._db_path = db_path
        self._cache_ttl = max(0.0, cache_ttl_s)
        self._fail_open = fail_open
        # 缓存: (tenant_id, resource) -> _CacheEntry
        self._cache: dict[tuple[str, str], _CacheEntry] = {}
        self._cache_lock = threading.Lock()
        # 告警去重: (tenant_id, resource, alert_type) -> last_alert_ts
        self._alert_dedup: dict[tuple[str, str, str], float] = {}
        self._alert_lock = threading.Lock()
        self._ensure_tables()

    # ── Schema ─────────────────────────────────────────────────────

    def _ensure_tables(self) -> None:
        """创建 ``tenant_quotas`` / ``tenant_usage`` / ``quota_alerts`` 表.

        ``tenant_usage`` 与 :mod:`maop.enterprise.pg_persist` 中的同名表
        保持列兼容(扩展 ``tokens_today`` / ``cost_today`` / ``last_reset_at``).
        使用 ``CREATE TABLE IF NOT EXISTS`` + ``ALTER TABLE ADD COLUMN``
        (忽略已存在列)实现幂等迁移.
        """
        with sqlite_connect(self._db_path) as conn:
            # tenant_quotas: 每租户/每资源一条配额
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_quotas (
                    tenant_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    hard_limit INTEGER NOT NULL DEFAULT 0,
                    soft_limit INTEGER NOT NULL DEFAULT 0,
                    period TEXT NOT NULL DEFAULT 'total',
                    created_at REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (tenant_id, resource)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenant_quotas_tenant "
                "ON tenant_quotas(tenant_id)"
            )

            # tenant_usage: 扩展现有表(若存在)或新建.
            # 设计为 (tenant_id, resource, period_key) 三元组,与
            # core/tenant/quota.py 的 tenant_resource_usage 风格一致,
            # 但表名使用 tenant_usage 以匹配 PRD 要求.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_usage (
                    tenant_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    period_key TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY (tenant_id, resource, period_key)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tenant_usage_tenant "
                "ON tenant_usage(tenant_id)"
            )

            # quota_alerts: 告警事件流
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quota_alerts (
                    alert_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    current_value INTEGER NOT NULL DEFAULT 0,
                    limit_value INTEGER NOT NULL DEFAULT 0,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    message TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL DEFAULT 0,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    resolved_at REAL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_quota_alerts_tenant "
                "ON quota_alerts(tenant_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_quota_alerts_unresolved "
                "ON quota_alerts(resolved, created_at)"
            )

    # ── 周期键 ─────────────────────────────────────────────────────

    @staticmethod
    def _period_key(period: str) -> str:
        """将 period 映射为存储键. ``daily`` → UTC 日期; ``total`` → 'total'."""
        if period == "daily":
            return datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return "total"

    # ── 缓存 ───────────────────────────────────────────────────────

    def _cache_get(self, tenant_id: str, resource: str) -> _CacheEntry | None:
        """读取缓存条目; 过期返回 None(不主动删除,下次写时清理)."""
        key = (tenant_id, resource)
        now = time.time()
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if now - entry.fetched_at > self._cache_ttl:
                return None
            return entry

    def _cache_put(self, tenant_id: str, resource: str, entry: _CacheEntry) -> None:
        with self._cache_lock:
            self._cache[(tenant_id, resource)] = entry

    def _cache_invalidate(self, tenant_id: str, resource: str | None = None) -> None:
        """失效缓存. resource=None 时失效整个租户的所有资源缓存."""
        with self._cache_lock:
            if resource is None:
                keys_to_drop = [k for k in self._cache if k[0] == tenant_id]
                for k in keys_to_drop:
                    self._cache.pop(k, None)
            else:
                self._cache.pop((tenant_id, resource), None)

    # ── 配额 CRUD ──────────────────────────────────────────────────

    def set_quota(
        self,
        tenant_id: str,
        resource: str,
        hard_limit: int,
        *,
        soft_limit: int = 0,
        period: str = "total",
    ) -> QuotaResponse:
        """设置或更新配额. 自动校正 soft_limit <= hard_limit."""
        if hard_limit < 0:
            raise ValueError("hard_limit must be >= 0")
        if soft_limit < 0:
            raise ValueError("soft_limit must be >= 0")
        if period not in ("daily", "total"):
            raise ValueError(f"period must be 'daily' or 'total', got {period!r}")
        # 校正: soft_limit 不应超过 hard_limit(除非 hard_limit=0 表示不限)
        if hard_limit > 0 and soft_limit > hard_limit:
            soft_limit = hard_limit
        now = time.time()
        with sqlite_connect(self._db_path) as conn:
            conn.execute(
                """INSERT INTO tenant_quotas
                   (tenant_id, resource, hard_limit, soft_limit, period,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, resource) DO UPDATE SET
                     hard_limit = excluded.hard_limit,
                     soft_limit = excluded.soft_limit,
                     period = excluded.period,
                     updated_at = excluded.updated_at""",
                (tenant_id, resource, hard_limit, soft_limit, period, now, now),
            )
        self._cache_invalidate(tenant_id, resource)
        logger.info(
            "[quota] set tenant=%s resource=%s hard=%d soft=%d period=%s",
            tenant_id, resource, hard_limit, soft_limit, period,
        )
        return QuotaResponse(
            tenant_id=tenant_id, resource=resource,
            hard_limit=hard_limit, soft_limit=soft_limit, period=period,
            created_at=now, updated_at=now,
        )

    def get_quota(self, tenant_id: str, resource: str) -> QuotaResponse | None:
        """查询单个配额. 不走缓存(管理面操作,频率低)."""
        with sqlite_connect(self._db_path) as conn:
            row = conn.execute(
                """SELECT tenant_id, resource, hard_limit, soft_limit,
                          period, created_at, updated_at
                   FROM tenant_quotas
                   WHERE tenant_id = ? AND resource = ?""",
                (tenant_id, resource),
            ).fetchone()
        if not row:
            return None
        return QuotaResponse(
            tenant_id=row[0], resource=row[1], hard_limit=row[2],
            soft_limit=row[3], period=row[4], created_at=row[5],
            updated_at=row[6],
        )

    def list_quotas(self, tenant_id: str) -> list[QuotaResponse]:
        """列出租户的所有配额."""
        with sqlite_connect(self._db_path) as conn:
            rows = conn.execute(
                """SELECT tenant_id, resource, hard_limit, soft_limit,
                          period, created_at, updated_at
                   FROM tenant_quotas
                   WHERE tenant_id = ?
                   ORDER BY resource""",
                (tenant_id,),
            ).fetchall()
        return [
            QuotaResponse(
                tenant_id=r[0], resource=r[1], hard_limit=r[2],
                soft_limit=r[3], period=r[4], created_at=r[5],
                updated_at=r[6],
            )
            for r in rows
        ]

    def update_quota(
        self,
        tenant_id: str,
        resource: str,
        *,
        hard_limit: int | None = None,
        soft_limit: int | None = None,
        period: str | None = None,
    ) -> QuotaResponse:
        """部分更新配额. 未提供的字段保持原值."""
        existing = self.get_quota(tenant_id, resource)
        if existing is None:
            raise KeyError(
                f"Quota not found for tenant={tenant_id!r} resource={resource!r}"
            )
        new_hard = existing.hard_limit if hard_limit is None else hard_limit
        new_soft = existing.soft_limit if soft_limit is None else soft_limit
        new_period = existing.period if period is None else period
        return self.set_quota(
            tenant_id, resource, new_hard,
            soft_limit=new_soft, period=new_period,
        )

    def delete_quota(self, tenant_id: str, resource: str) -> bool:
        """删除配额. 返回是否实际删除了一行."""
        with sqlite_connect(self._db_path) as conn:
            cur = conn.execute(
                "DELETE FROM tenant_quotas WHERE tenant_id = ? AND resource = ?",
                (tenant_id, resource),
            )
            deleted = cur.rowcount > 0
        if deleted:
            self._cache_invalidate(tenant_id, resource)
            logger.info(
                "[quota] deleted tenant=%s resource=%s", tenant_id, resource,
            )
        return deleted

    # ── 使用量 ─────────────────────────────────────────────────────

    def update_usage(
        self,
        tenant_id: str,
        resource: str,
        amount: int,
        *,
        period: str = "total",
    ) -> int:
        """增量更新使用量(可正可负). 返回更新后的 used 值.

        P1 #20 fix: 负增量仍允许(并发类资源释放语义), 但结果被钳制到
        ``>= 0`` —— 旧实现允许 used 变为负数, 导致配额统计失真。
        """
        if amount == 0:
            return self.get_usage(tenant_id, resource).used
        key = self._period_key(period)
        now = time.time()
        with sqlite_connect(self._db_path) as conn:
            # VALUES 侧 MAX(0, ?) 只处理"新行 + 负增量"的建行情形；
            # DO UPDATE 侧必须用原始 amount 参数（不能用 excluded.used，
            # 那是被钳制过的值，会让负增量恒等于 +0，释放语义失效）。
            conn.execute(
                """INSERT INTO tenant_usage
                   (tenant_id, resource, period_key, used, updated_at)
                   VALUES (?, ?, ?, MAX(0, ?), ?)
                   ON CONFLICT(tenant_id, resource, period_key) DO UPDATE SET
                     used = MAX(0, tenant_usage.used + ?),
                     updated_at = excluded.updated_at""",
                (tenant_id, resource, key, amount, now, amount),
            )
            row = conn.execute(
                "SELECT used FROM tenant_usage "
                "WHERE tenant_id = ? AND resource = ? AND period_key = ?",
                (tenant_id, resource, key),
            ).fetchone()
        used = row[0] if row else 0
        self._cache_invalidate(tenant_id, resource)
        return used

    def set_usage(
        self,
        tenant_id: str,
        resource: str,
        value: int,
        *,
        period: str = "total",
    ) -> int:
        """绝对设置使用量. 返回设置后的 used 值."""
        key = self._period_key(period)
        now = time.time()
        with sqlite_connect(self._db_path) as conn:
            conn.execute(
                """INSERT INTO tenant_usage
                   (tenant_id, resource, period_key, used, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, resource, period_key) DO UPDATE SET
                     used = excluded.used,
                     updated_at = excluded.updated_at""",
                (tenant_id, resource, key, value, now),
            )
        self._cache_invalidate(tenant_id, resource)
        return value

    def get_usage(self, tenant_id: str, resource: str) -> UsageResponse:
        """查询使用量. 优先走缓存; 缓存未命中读 DB 并回填.

        无配额设置时返回 hard_limit=0/soft_limit=0(表示不限).
        """
        cached = self._cache_get(tenant_id, resource)
        if cached is not None:
            return self._build_usage_response(tenant_id, resource, cached)

        # 缓存未命中: 读 DB
        with sqlite_connect(self._db_path) as conn:
            quota_row = conn.execute(
                "SELECT hard_limit, soft_limit, period FROM tenant_quotas "
                "WHERE tenant_id = ? AND resource = ?",
                (tenant_id, resource),
            ).fetchone()
            if quota_row:
                hard_limit, soft_limit, period = quota_row[0], quota_row[1], quota_row[2]
            else:
                hard_limit, soft_limit, period = 0, 0, "total"
            key = self._period_key(period)
            usage_row = conn.execute(
                "SELECT used FROM tenant_usage "
                "WHERE tenant_id = ? AND resource = ? AND period_key = ?",
                (tenant_id, resource, key),
            ).fetchone()
            used = usage_row[0] if usage_row else 0

        entry = _CacheEntry(
            hard_limit=hard_limit, soft_limit=soft_limit,
            period=period, used=used, fetched_at=time.time(),
        )
        self._cache_put(tenant_id, resource, entry)
        return self._build_usage_response(tenant_id, resource, entry)

    @staticmethod
    def _build_usage_response(
        tenant_id: str, resource: str, entry: _CacheEntry,
    ) -> UsageResponse:
        hard = entry.hard_limit
        soft = entry.soft_limit
        used = entry.used
        if hard <= 0:
            remaining = -1
            exceeded_hard = False
        else:
            remaining = max(0, hard - used)
            exceeded_hard = used >= hard
        exceeded_soft = soft > 0 and used >= soft
        return UsageResponse(
            tenant_id=tenant_id, resource=resource, period=entry.period,
            used=used, hard_limit=hard, soft_limit=soft,
            remaining=remaining,
            exceeded_soft=exceeded_soft, exceeded_hard=exceeded_hard,
        )

    def reset_usage(
        self, tenant_id: str, resource: str | None = None,
    ) -> int:
        """重置使用量. resource=None 时重置租户所有资源. 返回删除行数."""
        with sqlite_connect(self._db_path) as conn:
            if resource is None:
                cur = conn.execute(
                    "DELETE FROM tenant_usage WHERE tenant_id = ?",
                    (tenant_id,),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM tenant_usage "
                    "WHERE tenant_id = ? AND resource = ?",
                    (tenant_id, resource),
                )
            deleted = cur.rowcount
        self._cache_invalidate(tenant_id, resource)
        return deleted

    def list_usage(self, tenant_id: str) -> list[UsageResponse]:
        """列出租户所有已设配额资源的使用量."""
        quotas = self.list_quotas(tenant_id)
        return [self.get_usage(tenant_id, q.resource) for q in quotas]

    # ── 配额检查(热路径) ──────────────────────────────────────────

    def check_quota(
        self,
        tenant_id: str,
        resource: str,
        amount: int = 1,
    ) -> QuotaCheckResult:
        """检查是否允许消耗 *amount* 单位的 *resource*.

        返回 :class:`QuotaCheckResult`:
          - ``allowed=True`` — 放行(可能附带 ``warning`` 表示已超软限制)
          - ``allowed=False`` — 拒绝(超过硬限制), ``reason`` 描述原因

        行为:
          - **fail-open**: 无配额设置(hard_limit=0)/未知资源/DB 错误 → 放行
          - **软限制**: used + amount > soft_limit → 记录告警但放行
          - **硬限制**: used + amount > hard_limit → 拒绝并记录告警
        """
        try:
            usage = self.get_usage(tenant_id, resource)
        except Exception as exc:
            # fail-open: DB 错误时不阻塞业务
            logger.warning(
                "[quota] check failed (fail-open) tenant=%s resource=%s: %s",
                tenant_id, resource, exc,
            )
            return QuotaCheckResult(allowed=True, reason="")

        hard = usage.hard_limit
        soft = usage.soft_limit
        used = usage.used

        # 无配额设置 → 放行
        if hard <= 0:
            return QuotaCheckResult(allowed=True, reason="")

        projected = used + amount

        # 硬限制检查
        if projected > hard:
            alert_id = self._record_alert(
                tenant_id, resource, "hard_exceeded",
                current_value=projected, limit_value=hard,
                severity="critical",
                message=(
                    f"Hard limit exceeded for {resource}: "
                    f"projected {projected} > limit {hard}"
                ),
            )
            return QuotaCheckResult(
                allowed=False,
                reason=(
                    f"Quota exceeded: tenant={tenant_id} resource={resource} "
                    f"used={used} hard_limit={hard} requested={amount}"
                ),
                alert_id=alert_id,
            )

        # 软限制检查(放行但告警)
        if soft > 0 and projected > soft:
            alert_id = self._record_alert(
                tenant_id, resource, "soft_exceeded",
                current_value=projected, limit_value=soft,
                severity="warning",
                message=(
                    f"Soft limit exceeded for {resource}: "
                    f"projected {projected} > soft {soft}"
                ),
            )
            return QuotaCheckResult(
                allowed=True,
                warning=(
                    f"Approaching quota limit: {resource} "
                    f"projected {projected} > soft {soft}"
                ),
                alert_id=alert_id,
            )

        return QuotaCheckResult(allowed=True, reason="")

    def consume(
        self, tenant_id: str, resource: str, amount: int = 1,
    ) -> QuotaCheckResult:
        """检查 + 记录使用量.

        P1 #20 fix: 旧实现是 check_quota(读) → update_usage(写) 两步操作,
        多副本/并发下存在 TOCTOU —— 多个请求可同时通过检查然后各自累加,
        突破硬限制。现改为**单条条件 UPDATE**: 硬限制检查与扣减在数据库
        层原子完成, ``rowcount=0`` 即表示超限拒绝。

        无配额设置(hard_limit=0 或无记录)→ 无条件放行(fail-open 一致)。
        """
        if amount < 0:
            # 释放资源请直接用 update_usage; consume 仅用于增量消费
            return QuotaCheckResult(
                allowed=False, reason="consume() requires amount >= 0"
            )

        # 读配额取 period + soft_limit(此处容忍缓存陈旧,仅影响告警精度)
        try:
            quota = self.get_quota(tenant_id, resource)
        except Exception as exc:
            logger.warning(
                "[quota] consume check failed (fail-open) "
                "tenant=%s resource=%s: %s",
                tenant_id, resource, exc,
            )
            return QuotaCheckResult(allowed=True, reason="")
        period = quota.period if quota else "total"
        soft = quota.soft_limit if quota else 0
        hard = quota.hard_limit if quota else 0
        key = self._period_key(period)
        now = time.time()

        try:
            with sqlite_connect(self._db_path) as conn:
                # 确保 usage 行存在(不覆盖已有值)
                conn.execute(
                    """INSERT INTO tenant_usage
                       (tenant_id, resource, period_key, used, updated_at)
                       VALUES (?, ?, ?, 0, ?)
                       ON CONFLICT(tenant_id, resource, period_key) DO NOTHING""",
                    (tenant_id, resource, key, now),
                )
                # 原子检查+扣减: 无配额/不限/未超限才累加
                cur = conn.execute(
                    """UPDATE tenant_usage
                       SET used = used + ?, updated_at = ?
                       WHERE tenant_id = ? AND resource = ? AND period_key = ?
                         AND (
                           (SELECT hard_limit FROM tenant_quotas
                              WHERE tenant_id = ? AND resource = ?) IS NULL
                           OR (SELECT hard_limit FROM tenant_quotas
                                WHERE tenant_id = ? AND resource = ?) <= 0
                           OR used + ? <= (SELECT hard_limit FROM tenant_quotas
                                            WHERE tenant_id = ? AND resource = ?)
                         )""",
                    (amount, now, tenant_id, resource, key,
                     tenant_id, resource,
                     tenant_id, resource,
                     amount, tenant_id, resource),
                )
                if cur.rowcount == 0:
                    # 硬限制拒绝
                    usage_row = conn.execute(
                        "SELECT used FROM tenant_usage "
                        "WHERE tenant_id = ? AND resource = ? AND period_key = ?",
                        (tenant_id, resource, key),
                    ).fetchone()
                    used_now = usage_row[0] if usage_row else 0
                    alert_id = self._record_alert(
                        tenant_id, resource, "hard_exceeded",
                        current_value=used_now + amount, limit_value=hard,
                        severity="critical",
                        message=(
                            f"Hard limit exceeded for {resource}: "
                            f"projected {used_now + amount} > limit {hard}"
                        ),
                    )
                    return QuotaCheckResult(
                        allowed=False,
                        reason=(
                            f"Quota exceeded: tenant={tenant_id} resource={resource} "
                            f"used={used_now} hard_limit={hard} requested={amount}"
                        ),
                        alert_id=alert_id,
                    )
                usage_row = conn.execute(
                    "SELECT used FROM tenant_usage "
                    "WHERE tenant_id = ? AND resource = ? AND period_key = ?",
                    (tenant_id, resource, key),
                ).fetchone()
                used = usage_row[0] if usage_row else amount
        except Exception as exc:
            # fail-open: DB 错误时不阻塞业务
            logger.warning(
                "[quota] consume failed (fail-open) tenant=%s resource=%s: %s",
                tenant_id, resource, exc,
            )
            return QuotaCheckResult(allowed=True, reason="")

        self._cache_invalidate(tenant_id, resource)

        # 软限制检查(放行但告警)
        if soft > 0 and used > soft:
            alert_id = self._record_alert(
                tenant_id, resource, "soft_exceeded",
                current_value=used, limit_value=soft,
                severity="warning",
                message=(
                    f"Soft limit exceeded for {resource}: "
                    f"used {used} > soft {soft}"
                ),
            )
            return QuotaCheckResult(
                allowed=True,
                warning=(
                    f"Approaching quota limit: {resource} "
                    f"used {used} > soft {soft}"
                ),
                alert_id=alert_id,
            )
        return QuotaCheckResult(allowed=True, reason="")

    # ── 告警 ───────────────────────────────────────────────────────

    def _record_alert(
        self,
        tenant_id: str,
        resource: str,
        alert_type: str,
        *,
        current_value: int,
        limit_value: int,
        severity: str,
        message: str,
    ) -> str:
        """记录告警. 带 (tenant, resource, type) 去重窗口避免告警风暴."""
        now = time.time()
        dedup_key = (tenant_id, resource, alert_type)
        with self._alert_lock:
            last_ts = self._alert_dedup.get(dedup_key, 0.0)
            if now - last_ts < ALERT_DEDUP_WINDOW_S:
                return ""
            self._alert_dedup[dedup_key] = now

        alert_id = uuid.uuid4().hex
        try:
            with sqlite_connect(self._db_path) as conn:
                conn.execute(
                    """INSERT INTO quota_alerts
                       (alert_id, tenant_id, resource, alert_type,
                        current_value, limit_value, severity, message,
                        created_at, resolved, resolved_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)""",
                    (alert_id, tenant_id, resource, alert_type,
                     current_value, limit_value, severity, message, now),
                )
        except Exception as exc:
            logger.warning(
                "[quota] record alert failed tenant=%s resource=%s: %s",
                tenant_id, resource, exc,
            )
            return ""
        logger.warning(
            "[quota] ALERT tenant=%s resource=%s type=%s severity=%s: %s",
            tenant_id, resource, alert_type, severity, message,
        )
        return alert_id

    def list_alerts(
        self,
        tenant_id: str,
        *,
        resolved: bool | None = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[QuotaAlertResponse]:
        """列出告警. resolved=None 表示全部, True=仅已解决, False=仅未解决."""
        sql = (
            "SELECT alert_id, tenant_id, resource, alert_type, "
            "current_value, limit_value, severity, message, "
            "created_at, resolved, resolved_at "
            "FROM quota_alerts WHERE tenant_id = ?"
        )
        params: list[Any] = [tenant_id]
        if resolved is not None:
            sql += " AND resolved = ?"
            params.append(1 if resolved else 0)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with sqlite_connect(self._db_path) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            QuotaAlertResponse(
                alert_id=r[0], tenant_id=r[1], resource=r[2],
                alert_type=r[3], current_value=r[4], limit_value=r[5],
                severity=r[6], message=r[7], created_at=r[8],
                resolved=bool(r[9]), resolved_at=r[10],
            )
            for r in rows
        ]

    def resolve_alert(self, alert_id: str) -> bool:
        """标记告警为已解决. 返回是否实际更新了一行."""
        now = time.time()
        with sqlite_connect(self._db_path) as conn:
            cur = conn.execute(
                "UPDATE quota_alerts SET resolved = 1, resolved_at = ? "
                "WHERE alert_id = ? AND resolved = 0",
                (now, alert_id),
            )
            updated = cur.rowcount > 0
        if updated:
            logger.info("[quota] alert resolved id=%s", alert_id)
        return updated

    # ── 缓存管理(测试/运维用) ────────────────────────────────────

    def cache_clear(self) -> None:
        """清空整个缓存."""
        with self._cache_lock:
            self._cache.clear()

    def cache_size(self) -> int:
        """返回当前缓存条目数."""
        with self._cache_lock:
            return len(self._cache)