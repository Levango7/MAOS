"""MAOP Enterprise Audit — Comprehensive Audit Logging.

Extends core audit with:
  - Structured audit events (who/what/when/where/result)
  - Tenant-scoped audit trails
  - Compliance-ready immutable log
  - Query/filter API for dashboard
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


def _coerce_event_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Normalise a DB row dict so ``AuditEvent(**row)`` succeeds.

    Older ``audit_events`` rows may lack the new enhancement columns
    (``risk_level`` / ``category`` / ``tags``). Pydantic will supply
    defaults for missing fields, but the ``action`` / ``severity``
    columns are stored as plain strings and must be valid enum values.
    This helper strips ``None`` values (which Pydantic v2 rejects for
    enum fields) and coerces ``tags`` from a JSON string when needed.
    """
    cleaned: dict[str, Any] = {}
    for k, v in row.items():
        if v is None:
            continue
        if k == "tags" and isinstance(v, str):
            try:
                import json
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    v = parsed
            except (json.JSONDecodeError, TypeError):
                v = []
        cleaned[k] = v
    return cleaned


class AuditAction(str, Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    API_CALL = "api_call"
    AGENT_EXECUTE = "agent_execute"
    CONFIG_CHANGE = "config_change"
    PERMISSION_CHANGE = "permission_change"
    TENANT_CREATE = "tenant_create"
    TENANT_UPDATE = "tenant_update"
    TENANT_DELETE = "tenant_delete"
    DATA_EXPORT = "data_export"
    DATA_ACCESS = "data_access"
    SECRET_ACCESS = "secret_access"
    SYSTEM_ADMIN = "system_admin"


class AuditSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditRiskLevel(str, Enum):
    """Risk level for audit events — used by alert rules and dashboards.

    Distinct from ``AuditSeverity`` which reflects log verbosity;
    ``risk_level`` reflects business-impact severity for alerting.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    event_id: str = ""
    timestamp: float = 0.0
    action: AuditAction = AuditAction.API_CALL
    severity: AuditSeverity = AuditSeverity.INFO
    actor: str = ""
    tenant_id: str = ""
    resource: str = ""
    detail: str = ""
    result: str = ""
    ip_address: str = ""
    user_agent: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    # ── Enhancement (audit-enhancement PRD) ────────────────────────
    risk_level: AuditRiskLevel = AuditRiskLevel.LOW
    category: str = ""  # e.g. "auth", "data", "system", "config"
    tags: list[str] = Field(default_factory=list)


class SqliteAuditStore:
    """SQLite-backed audit event persistence (P1 #11).

    当 PostgreSQL 不可用时提供持久化兜底，避免审计事件只留在内存
    （进程重启即丢失，违反合规留存要求）。接口与
    :class:`maop.enterprise.pg_persist.PgAuditStore` 对齐：
    ``available`` / ``save_event`` / ``query_events`` / ``summary``。

    数据库文件：``$MAOP_DATA_DIR/audit.db``（默认 ``data/audit.db``），
    WAL 模式 + 线程锁，与 notification store 同一模板。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            data_dir = Path(os.getenv("MAOP_DATA_DIR", "data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "audit.db"
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._ok = True
        try:
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp REAL NOT NULL,
                        action TEXT NOT NULL,
                        severity TEXT DEFAULT 'info',
                        actor TEXT DEFAULT '',
                        tenant_id TEXT DEFAULT '',
                        resource TEXT DEFAULT '',
                        detail TEXT DEFAULT '',
                        result TEXT DEFAULT 'success',
                        ip_address TEXT DEFAULT '',
                        user_agent TEXT DEFAULT '',
                        metadata TEXT DEFAULT '{}',
                        risk_level TEXT DEFAULT 'low',
                        category TEXT DEFAULT '',
                        tags TEXT DEFAULT '[]'
                    )
                """)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp "
                    "ON audit_events(timestamp)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_tenant "
                    "ON audit_events(tenant_id)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_action "
                    "ON audit_events(action)"
                )
        except Exception as exc:
            # 初始化失败（磁盘只读等）→ 标记不可用，调用方回退内存
            self._ok = False
            logger.warning("[audit] SQLite audit store unavailable: %s", exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @property
    def available(self) -> bool:
        return self._ok

    def save_event(self, event: dict[str, Any]) -> None:
        if not self._ok:
            return
        with self._lock, self._connect() as conn:
            # P0 修复：INSERT OR REPLACE → INSERT OR IGNORE。审计日志是
            # 合规证据链，同一 event_id 不得被覆盖改写（旧实现用 REPLACE
            # 允许以相同 event_id 覆盖历史记录，破坏"不可变日志"承诺）。
            # event_id 为 UUID 随机生成，冲突概率可忽略；发生冲突宁可
            # 丢弃本次也不覆盖已有证据。
            conn.execute(
                """INSERT OR IGNORE INTO audit_events
                      (event_id, timestamp, action, severity, actor, tenant_id,
                       resource, detail, result, ip_address, user_agent, metadata,
                       risk_level, category, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.get("event_id", ""), event.get("timestamp", 0),
                    event.get("action", ""), event.get("severity", "info"),
                    event.get("actor", ""), event.get("tenant_id", ""),
                    event.get("resource", ""), event.get("detail", ""),
                    event.get("result", "success"), event.get("ip_address", ""),
                    event.get("user_agent", ""),
                    json.dumps(event.get("metadata", {})),
                    event.get("risk_level", "low"), event.get("category", ""),
                    json.dumps(event.get("tags", [])),
                ),
            )

    def query_events(
        self,
        *,
        actor: str = "",
        tenant_id: str = "",
        action: str = "",
        severity: str = "",
        since: float = 0.0,
        limit: int = 100,
        risk_level: str = "",
        category: str = "",
        resource: str = "",
        result: str = "",
    ) -> list[dict[str, Any]]:
        if not self._ok:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in (
            ("actor", actor), ("tenant_id", tenant_id), ("action", action),
            ("severity", severity), ("risk_level", risk_level),
            ("category", category), ("resource", resource), ("result", result),
        ):
            if val:
                clauses.append(f"{col}=?")
                params.append(val)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ?",
                tuple(params),
            ).fetchall()
        return [dict(r) for r in rows]

    def summary(self, tenant_id: str = "", hours: int = 24) -> dict[str, Any]:
        if not self._ok:
            return {"total_events": 0, "by_action": {}, "critical_count": 0, "hours": hours}
        since = time.time() - hours * 3600
        clauses = ["timestamp >= ?"]
        params: list[Any] = [since]
        if tenant_id:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}"
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT action, severity, risk_level, category FROM audit_events {where}",
                tuple(params),
            ).fetchall()
        by_action: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_category: dict[str, int] = {}
        critical = 0
        for r in rows:
            a = r["action"] or ""
            by_action[a] = by_action.get(a, 0) + 1
            rl = r["risk_level"] or "low"
            by_risk[rl] = by_risk.get(rl, 0) + 1
            cat = r["category"] or "uncategorised"
            by_category[cat] = by_category.get(cat, 0) + 1
            if r["severity"] == "critical":
                critical += 1
        return {
            "total_events": len(rows),
            "by_action": by_action,
            "by_risk_level": by_risk,
            "by_category": by_category,
            "critical_count": critical,
            "hours": hours,
        }


class EnterpriseAuditLogger:
    """Enterprise audit trail logger with tenant scoping.

    持久化优先级（P1 #11）：PostgreSQL > SQLite > 内存。
    内存仅作最后兜底（测试/无磁盘环境），生产环境应配置 PG 或
    保证 ``MAOP_DATA_DIR`` 可写以启用 SQLite 兜底。
    """

    def __init__(self, alert_engine: Any = None) -> None:
        require_feature(FeatureFlag.AUDIT_LOG)
        self._events: list[AuditEvent] = []
        self._max_events: int = 100000
        self._pg: PgAuditStore | None = None
        self._sqlite: SqliteAuditStore | None = None
        # P0 修复：可选注入告警引擎（audit_enhanced.AuditAlertEngine）。
        # 此前该引擎全仓库零调用点（死代码），规则永不触发；现在 log()
        # 每条事件都会送入引擎评估。不注入则保持原有行为。
        self._alert_engine: Any = alert_engine
        try:
            from maop.enterprise.pg_persist import PgAuditStore
            pg = PgAuditStore()
            if pg.available:
                self._pg = pg
        except Exception as e:
            logger.debug("ignored: %s", e, exc_info=True)
        if self._pg is None:
            try:
                store = SqliteAuditStore()
                if store.available:
                    self._sqlite = store
                    logger.info(
                        "[audit] using SQLite audit store at %s (PG unavailable)",
                        store.db_path,
                    )
            except Exception as e:
                logger.warning("[audit] SQLite audit fallback failed: %s", e)

    def log(
        self,
        action: AuditAction,
        actor: str = "",
        *,
        tenant_id: str = "",
        resource: str = "",
        detail: str = "",
        result: str = "success",
        severity: AuditSeverity = AuditSeverity.INFO,
        ip_address: str = "",
        metadata: dict[str, Any] | None = None,
        risk_level: AuditRiskLevel | None = None,
        category: str = "",
        tags: list[str] | None = None,
        user_agent: str = "",
    ) -> AuditEvent:
        now = time.time()
        # Auto-derive risk_level from severity when not explicitly provided.
        if risk_level is None:
            risk_level = {
                AuditSeverity.INFO: AuditRiskLevel.LOW,
                AuditSeverity.WARNING: AuditRiskLevel.MEDIUM,
                AuditSeverity.CRITICAL: AuditRiskLevel.CRITICAL,
            }.get(severity, AuditRiskLevel.LOW)
        event = AuditEvent(
            # P1 #11: UUID 替代 时间戳+序号（旧格式可预测，攻击者可枚举/伪造）
            event_id=f"aud_{uuid.uuid4().hex}",
            timestamp=now, action=action, severity=severity,
            actor=actor, tenant_id=tenant_id, resource=resource,
            detail=detail, result=result, ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            risk_level=risk_level, category=category,
            tags=tags or [],
        )
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]
        # 持久化：PG 优先；PG 写入异常时降级 SQLite（不阻断业务，P1 #11）
        persisted = False
        if self._pg:
            try:
                self._pg.save_event(event.model_dump())
                persisted = True
            except Exception as exc:
                logger.warning("[audit] PG save failed, falling back to SQLite: %s", exc)
        if not persisted and self._sqlite:
            try:
                self._sqlite.save_event(event.model_dump())
            except Exception as exc:
                logger.warning("[audit] SQLite save failed (in-memory only): %s", exc)
        # P0 修复：告警引擎接线 —— 事件评估失败不阻断审计主流程
        if self._alert_engine is not None:
            try:
                self._alert_engine.evaluate_event(event)
            except Exception as exc:
                logger.warning("[audit] alert engine evaluation failed: %s", exc)
        if severity == AuditSeverity.CRITICAL:
            logger.critical("[audit] %s actor=%s tenant=%s resource=%s result=%s",
                            action.value, actor, tenant_id, resource, result)
        else:
            logger.info("[audit] %s actor=%s tenant=%s resource=%s", action.value, actor, tenant_id, resource)
        return event

    def query(
        self,
        *,
        actor: str = "",
        tenant_id: str = "",
        action: AuditAction | None = None,
        severity: AuditSeverity | None = None,
        since: float = 0.0,
        limit: int = 100,
        risk_level: AuditRiskLevel | None = None,
        category: str = "",
        tags: list[str] | None = None,
        resource: str = "",
        result: str = "",
    ) -> list[AuditEvent]:
        # P0 修复：tags 过滤在所有后端统一生效（旧实现只在内存分支
        # 过滤，PG/SQLite 分支静默忽略 tags 参数 → 返回未过滤结果）。
        if self._pg and self._pg.available:
            rows = self._pg.query_events(
                actor=actor, tenant_id=tenant_id,
                action=action.value if action else "",
                severity=severity.value if severity else "",
                since=since, limit=limit,
                risk_level=risk_level.value if risk_level else "",
                category=category,
                resource=resource, result=result,
            )
            result_list = [AuditEvent(**_coerce_event_dict(r)) for r in rows]
            if tags:
                result_list = [
                    e for e in result_list if all(t in e.tags for t in tags)
                ]
            return result_list
        if self._sqlite and self._sqlite.available:
            rows = self._sqlite.query_events(
                actor=actor, tenant_id=tenant_id,
                action=action.value if action else "",
                severity=severity.value if severity else "",
                since=since, limit=limit,
                risk_level=risk_level.value if risk_level else "",
                category=category,
                resource=resource, result=result,
            )
            result_list = [AuditEvent(**_coerce_event_dict(r)) for r in rows]
            if tags:
                result_list = [
                    e for e in result_list if all(t in e.tags for t in tags)
                ]
            return result_list
        result_list = self._events
        if actor:
            result_list = [e for e in result_list if e.actor == actor]
        if tenant_id:
            result_list = [e for e in result_list if e.tenant_id == tenant_id]
        if action:
            result_list = [e for e in result_list if e.action == action]
        if severity:
            result_list = [e for e in result_list if e.severity == severity]
        if risk_level:
            result_list = [e for e in result_list if e.risk_level == risk_level]
        if category:
            result_list = [e for e in result_list if e.category == category]
        if resource:
            result_list = [e for e in result_list if e.resource == resource]
        if result:
            result_list = [e for e in result_list if e.result == result]
        if tags:
            result_list = [e for e in result_list if all(t in e.tags for t in tags)]
        if since:
            result_list = [e for e in result_list if e.timestamp >= since]
        return result_list[-limit:]

    def summary(self, tenant_id: str = "", hours: int = 24) -> dict[str, Any]:
        if self._pg and self._pg.available:
            return self._pg.summary(tenant_id=tenant_id, hours=hours)
        if self._sqlite and self._sqlite.available:
            return self._sqlite.summary(tenant_id=tenant_id, hours=hours)
        since = time.time() - hours * 3600
        events = [e for e in self._events if e.timestamp >= since]
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        action_counts: dict[str, int] = {}
        risk_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for e in events:
            action_counts[e.action.value] = action_counts.get(e.action.value, 0) + 1
            risk_counts[e.risk_level.value] = risk_counts.get(e.risk_level.value, 0) + 1
            cat = e.category or "uncategorised"
            category_counts[cat] = category_counts.get(cat, 0) + 1
        return {
            "total_events": len(events),
            "by_action": action_counts,
            "by_risk_level": risk_counts,
            "by_category": category_counts,
            "critical_count": sum(1 for e in events if e.severity == AuditSeverity.CRITICAL),
            "hours": hours,
        }
