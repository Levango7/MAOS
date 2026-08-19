"""MAOP Enterprise Audit — Comprehensive Audit Logging.

Extends core audit with:
  - Structured audit events (who/what/when/where/result)
  - Tenant-scoped audit trails
  - Compliance-ready immutable log
  - Query/filter API for dashboard
"""

from __future__ import annotations

import logging
import time
from enum import Enum
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


class EnterpriseAuditLogger:
    """Enterprise audit trail logger with tenant scoping and optional PG persistence."""

    def __init__(self) -> None:
        require_feature(FeatureFlag.AUDIT_LOG)
        self._events: list[AuditEvent] = []
        self._max_events: int = 100000
        self._pg: PgAuditStore | None = None
        try:
            from maop.enterprise.pg_persist import PgAuditStore
            pg = PgAuditStore()
            if pg.available:
                self._pg = pg
        except Exception as e:
            logger.debug("ignored: %s", e, exc_info=True)

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
            event_id=f"aud_{int(now * 1000)}_{len(self._events)}",
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
        if self._pg:
            self._pg.save_event(event.model_dump())
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
            return [AuditEvent(**_coerce_event_dict(r)) for r in rows]
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
