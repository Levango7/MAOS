"""MAOP Enterprise PostgreSQL Persistence Layer.

Provides PostgreSQL-backed storage for enterprise modules:
  - RBAC grants
  - Tenant data + quotas
  - Audit events

Each manager auto-creates its schema on first use.
Uses the shared StorageBackend abstraction so the same code works
with SQLite (personal) or PostgreSQL (enterprise) transparently.

When PostgreSQL is unavailable, falls back to in-memory storage
with a degradation warning (matching the existing behavior).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, cast

from maop.config.edition import FeatureFlag, has_feature, record_degradation

logger = logging.getLogger(__name__)


def _get_pg_backend() -> Any | None:
    if not has_feature(FeatureFlag.POSTGRESQL):
        return None
    backend_type = os.getenv("MAOP_STORAGE_BACKEND", "").lower()
    if backend_type != "postgresql":
        return None
    try:
        from maop.core.backends.backends_pg import PostgreSQLStorageBackend
        return PostgreSQLStorageBackend()
    except ImportError:
        record_degradation("storage", "postgresql", "memory")
        return None


class PgRBACStore:
    """PostgreSQL-backed RBAC grant persistence."""

    def __init__(self) -> None:
        self._backend = _get_pg_backend()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self._backend:
            return
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS rbac_grants (
                id SERIAL PRIMARY KEY,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id TEXT DEFAULT '',
                granted_by TEXT DEFAULT '',
                granted_at DOUBLE PRECISION DEFAULT 0,
                expires_at DOUBLE PRECISION DEFAULT NULL,
                UNIQUE(user_id, role, tenant_id)
            )
        """)
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_rbac_user ON rbac_grants(user_id)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_rbac_tenant ON rbac_grants(tenant_id)")

    @property
    def available(self) -> bool:
        return self._backend is not None

    def save_grant(self, user_id: str, role: str, tenant_id: str, granted_by: str, granted_at: float, expires_at: float | None) -> None:
        if not self._backend:
            return
        self._backend.execute(
            """INSERT INTO rbac_grants (user_id, role, tenant_id, granted_by, granted_at, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (user_id, role, tenant_id) DO UPDATE SET granted_by=EXCLUDED.granted_by, granted_at=EXCLUDED.granted_at, expires_at=EXCLUDED.expires_at""",
            (user_id, role, tenant_id, granted_by, granted_at, expires_at),
        )

    def delete_grant(self, user_id: str, role: str, tenant_id: str) -> bool:
        if not self._backend:
            return False
        self._backend.execute(
            "DELETE FROM rbac_grants WHERE user_id=%s AND role=%s AND tenant_id=%s",
            (user_id, role, tenant_id),
        )
        return True

    def load_grants(self, user_id: str = "", tenant_id: str = "") -> list[dict[str, Any]]:
        if not self._backend:
            return []
        if user_id and tenant_id:
            return cast(list[dict[str, Any]], self._backend.fetchall(
                "SELECT * FROM rbac_grants WHERE user_id=%s AND (tenant_id=%s OR tenant_id='')",
                (user_id, tenant_id),
            ))
        if user_id:
            return cast(list[dict[str, Any]], self._backend.fetchall("SELECT * FROM rbac_grants WHERE user_id=%s", (user_id,)))
        if tenant_id:
            return cast(list[dict[str, Any]], self._backend.fetchall("SELECT * FROM rbac_grants WHERE tenant_id=%s OR tenant_id=''", (tenant_id,)))
        return cast(list[dict[str, Any]], self._backend.fetchall("SELECT * FROM rbac_grants"))


class PgTenantStore:
    """PostgreSQL-backed tenant persistence."""

    def __init__(self) -> None:
        self._backend = _get_pg_backend()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self._backend:
            return
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT DEFAULT 'trial',
                plan TEXT DEFAULT 'starter',
                quota JSONB DEFAULT '{}',
                created_at DOUBLE PRECISION DEFAULT 0,
                updated_at DOUBLE PRECISION DEFAULT 0,
                expires_at DOUBLE PRECISION DEFAULT NULL,
                metadata JSONB DEFAULT '{}'
            )
        """)
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS tenant_usage (
                tenant_id TEXT PRIMARY KEY,
                api_calls_today INTEGER DEFAULT 0,
                storage_mb REAL DEFAULT 0,
                active_agents INTEGER DEFAULT 0,
                concurrent_tasks INTEGER DEFAULT 0,
                active_users INTEGER DEFAULT 0,
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
            )
        """)

    @property
    def available(self) -> bool:
        return self._backend is not None

    def save_tenant(self, data: dict[str, Any]) -> None:
        if not self._backend:
            return
        quota = json.dumps(data.get("quota", {}))
        meta = json.dumps(data.get("metadata", {}))
        self._backend.execute(
            """INSERT INTO tenants (tenant_id, name, status, plan, quota, created_at, updated_at, expires_at, metadata)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id) DO UPDATE SET name=EXCLUDED.name, status=EXCLUDED.status, plan=EXCLUDED.plan,
               quota=EXCLUDED.quota, updated_at=EXCLUDED.updated_at, expires_at=EXCLUDED.expires_at, metadata=EXCLUDED.metadata""",
            (data["tenant_id"], data["name"], data.get("status", "trial"), data.get("plan", "starter"),
             quota, data.get("created_at", 0), data.get("updated_at", 0), data.get("expires_at"), meta),
        )

    def delete_tenant(self, tenant_id: str) -> bool:
        if not self._backend:
            return False
        self._backend.execute("DELETE FROM tenant_usage WHERE tenant_id=%s", (tenant_id,))
        self._backend.execute("DELETE FROM tenants WHERE tenant_id=%s", (tenant_id,))
        return True

    def load_tenants(self, status: str = "") -> list[dict[str, Any]]:
        if not self._backend:
            return []
        if status:
            return cast(list[dict[str, Any]], self._backend.fetchall("SELECT * FROM tenants WHERE status=%s", (status,)))
        return cast(list[dict[str, Any]], self._backend.fetchall("SELECT * FROM tenants"))

    def load_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        if not self._backend:
            return None
        return cast(dict[str, Any] | None, self._backend.fetchone("SELECT * FROM tenants WHERE tenant_id=%s", (tenant_id,)))

    def save_usage(self, tenant_id: str, usage: dict[str, Any]) -> None:
        if not self._backend:
            return
        self._backend.execute(
            """INSERT INTO tenant_usage (tenant_id, api_calls_today, storage_mb, active_agents, concurrent_tasks, active_users)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (tenant_id) DO UPDATE SET api_calls_today=EXCLUDED.api_calls_today, storage_mb=EXCLUDED.storage_mb,
               active_agents=EXCLUDED.active_agents, concurrent_tasks=EXCLUDED.concurrent_tasks, active_users=EXCLUDED.active_users""",
            (tenant_id, usage.get("api_calls_today", 0), usage.get("storage_mb", 0),
             usage.get("active_agents", 0), usage.get("concurrent_tasks", 0), usage.get("active_users", 0)),
        )

    def load_usage(self, tenant_id: str) -> dict[str, Any] | None:
        if not self._backend:
            return None
        return cast(dict[str, Any] | None, self._backend.fetchone("SELECT * FROM tenant_usage WHERE tenant_id=%s", (tenant_id,)))


class PgAuditStore:
    """PostgreSQL-backed audit event persistence."""

    def __init__(self) -> None:
        self._backend = _get_pg_backend()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self._backend:
            return
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                timestamp DOUBLE PRECISION NOT NULL,
                action TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                actor TEXT DEFAULT '',
                tenant_id TEXT DEFAULT '',
                resource TEXT DEFAULT '',
                detail TEXT DEFAULT '',
                result TEXT DEFAULT 'success',
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                metadata JSONB DEFAULT '{}'
            )
        """)
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action)")
        # ── Audit enhancement: add risk_level / category / tags columns ──
        # Use try/except around ALTER TABLE ADD COLUMN since the column may
        # already exist on upgraded schemas; the duplicate-column error is
        # safe to swallow.
        for col_def in (
            "risk_level TEXT DEFAULT 'low'",
            "category TEXT DEFAULT ''",
            "tags JSONB DEFAULT '[]'",
        ):
            try:
                self._backend.execute(f"ALTER TABLE audit_events ADD COLUMN {col_def}")
            except Exception:
                logger.debug('swallowed exception', exc_info=True)
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_risk_level ON audit_events(risk_level)"
        )
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_events(category)"
        )

    @property
    def available(self) -> bool:
        return self._backend is not None

    def save_event(self, event: dict[str, Any]) -> None:
        if not self._backend:
            return
        meta = json.dumps(event.get("metadata", {}))
        tags = json.dumps(event.get("tags", []))
        self._backend.execute(
            """INSERT INTO audit_events
                  (event_id, timestamp, action, severity, actor, tenant_id,
                   resource, detail, result, ip_address, user_agent, metadata,
                   risk_level, category, tags)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (event.get("event_id", ""), event.get("timestamp", 0), event.get("action", ""),
             event.get("severity", "info"), event.get("actor", ""), event.get("tenant_id", ""),
             event.get("resource", ""), event.get("detail", ""), event.get("result", "success"),
             event.get("ip_address", ""), event.get("user_agent", ""), meta,
             event.get("risk_level", "low"), event.get("category", ""), tags),
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
        if not self._backend:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if actor:
            clauses.append("actor=%s")
            params.append(actor)
        if tenant_id:
            clauses.append("tenant_id=%s")
            params.append(tenant_id)
        if action:
            clauses.append("action=%s")
            params.append(action)
        if severity:
            clauses.append("severity=%s")
            params.append(severity)
        if risk_level:
            clauses.append("risk_level=%s")
            params.append(risk_level)
        if category:
            clauses.append("category=%s")
            params.append(category)
        if resource:
            clauses.append("resource=%s")
            params.append(resource)
        if result:
            clauses.append("result=%s")
            params.append(result)
        if since:
            clauses.append("timestamp >= %s")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        return cast(list[dict[str, Any]], self._backend.fetchall(
            f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT %s",
            tuple(params),
        ))

    def summary(self, tenant_id: str = "", hours: int = 24) -> dict[str, Any]:
        if not self._backend:
            return {"total_events": 0, "by_action": {}, "critical_count": 0, "hours": hours}
        since = time.time() - hours * 3600
        clauses = ["timestamp >= %s"]
        params: list[Any] = [since]
        if tenant_id:
            clauses.append("tenant_id=%s")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}"
        rows = self._backend.fetchall(
            f"SELECT action, severity, risk_level, category FROM audit_events {where}",
            tuple(params),
        )
        by_action: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_category: dict[str, int] = {}
        critical = 0
        for r in rows:
            a = r.get("action", "")
            by_action[a] = by_action.get(a, 0) + 1
            rl = r.get("risk_level") or "low"
            by_risk[rl] = by_risk.get(rl, 0) + 1
            cat = r.get("category") or "uncategorised"
            by_category[cat] = by_category.get(cat, 0) + 1
            if r.get("severity") == "critical":
                critical += 1
        return {
            "total_events": len(rows),
            "by_action": by_action,
            "by_risk_level": by_risk,
            "by_category": by_category,
            "critical_count": critical,
            "hours": hours,
        }


class PgAuditAlertStore:
    """PostgreSQL-backed persistence for audit alert rules and history.

    Schema (auto-created on first use):

    - ``audit_alert_rules``: alert rule definitions (condition, action, etc.)
    - ``audit_alert_history``: triggered alert records with acknowledgement state

    Falls back to no-op (``available=False``) when PostgreSQL is unavailable;
    callers should keep an in-memory mirror so personal edition still works.
    """

    def __init__(self) -> None:
        self._backend = _get_pg_backend()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self._backend:
            return
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS audit_alert_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                enabled INTEGER DEFAULT 1,
                condition_type TEXT NOT NULL,
                condition JSONB NOT NULL DEFAULT '{}',
                action TEXT DEFAULT 'notify',
                action_config JSONB DEFAULT '{}',
                severity TEXT DEFAULT 'warning',
                tenant_id TEXT DEFAULT '',
                created_at DOUBLE PRECISION DEFAULT 0,
                updated_at DOUBLE PRECISION DEFAULT 0,
                created_by TEXT DEFAULT ''
            )
        """)
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant ON audit_alert_rules(tenant_id)"
        )
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON audit_alert_rules(enabled)"
        )
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS audit_alert_history (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                triggered_at DOUBLE PRECISION NOT NULL,
                event_id TEXT DEFAULT '',
                severity TEXT DEFAULT 'warning',
                message TEXT DEFAULT '',
                acknowledged INTEGER DEFAULT 0,
                acknowledged_by TEXT DEFAULT '',
                acknowledged_at DOUBLE PRECISION DEFAULT NULL,
                tenant_id TEXT DEFAULT '',
                metadata JSONB DEFAULT '{}'
            )
        """)
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_history_rule ON audit_alert_history(rule_id)"
        )
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_history_ts ON audit_alert_history(triggered_at)"
        )
        self._backend.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_history_ack ON audit_alert_history(acknowledged)"
        )

    @property
    def available(self) -> bool:
        return self._backend is not None

    # ── Rule CRUD ──────────────────────────────────────────────────
    def save_rule(self, rule: dict[str, Any]) -> None:
        if not self._backend:
            return
        self._backend.execute(
            """INSERT INTO audit_alert_rules
                  (rule_id, name, description, enabled, condition_type, condition,
                   action, action_config, severity, tenant_id,
                   created_at, updated_at, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (rule_id) DO UPDATE SET
                   name=EXCLUDED.name, description=EXCLUDED.description,
                   enabled=EXCLUDED.enabled, condition_type=EXCLUDED.condition_type,
                   condition=EXCLUDED.condition, action=EXCLUDED.action,
                   action_config=EXCLUDED.action_config, severity=EXCLUDED.severity,
                   updated_at=EXCLUDED.updated_at""",
            (rule["rule_id"], rule.get("name", ""), rule.get("description", ""),
             1 if rule.get("enabled", True) else 0, rule.get("condition_type", "threshold"),
             json.dumps(rule.get("condition", {})), rule.get("action", "notify"),
             json.dumps(rule.get("action_config", {})), rule.get("severity", "warning"),
             rule.get("tenant_id", ""), rule.get("created_at", 0),
             rule.get("updated_at", 0), rule.get("created_by", "")),
        )

    def delete_rule(self, rule_id: str) -> bool:
        if not self._backend:
            return False
        self._backend.execute("DELETE FROM audit_alert_rules WHERE rule_id=%s", (rule_id,))
        return True

    def load_rules(self, tenant_id: str = "", enabled_only: bool = False) -> list[dict[str, Any]]:
        if not self._backend:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id:
            clauses.append("tenant_id=%s")
            params.append(tenant_id)
        if enabled_only:
            clauses.append("enabled=1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = cast(list[dict[str, Any]], self._backend.fetchall(
            f"SELECT * FROM audit_alert_rules {where} ORDER BY created_at DESC",
            tuple(params),
        ))
        return [_coerce_rule_row(r) for r in rows]

    def load_rule(self, rule_id: str) -> dict[str, Any] | None:
        if not self._backend:
            return None
        row = cast(dict[str, Any] | None, self._backend.fetchone(
            "SELECT * FROM audit_alert_rules WHERE rule_id=%s", (rule_id,),
        ))
        if row is None:
            return None
        return _coerce_rule_row(row)

    # ── Alert history ──────────────────────────────────────────────
    def save_alert(self, alert: dict[str, Any]) -> None:
        if not self._backend:
            return
        self._backend.execute(
            """INSERT INTO audit_alert_history
                  (alert_id, rule_id, triggered_at, event_id, severity, message,
                   acknowledged, acknowledged_by, acknowledged_at, tenant_id, metadata)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (alert["alert_id"], alert.get("rule_id", ""), alert.get("triggered_at", 0),
             alert.get("event_id", ""), alert.get("severity", "warning"),
             alert.get("message", ""),
             1 if alert.get("acknowledged", False) else 0,
             alert.get("acknowledged_by", ""), alert.get("acknowledged_at"),
             alert.get("tenant_id", ""), json.dumps(alert.get("metadata", {}))),
        )

    def load_alerts(
        self,
        *,
        rule_id: str = "",
        tenant_id: str = "",
        acknowledged: bool | None = None,
        since: float = 0.0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not self._backend:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if rule_id:
            clauses.append("rule_id=%s")
            params.append(rule_id)
        if tenant_id:
            clauses.append("tenant_id=%s")
            params.append(tenant_id)
        if acknowledged is not None:
            clauses.append("acknowledged=%s")
            params.append(1 if acknowledged else 0)
        if since:
            clauses.append("triggered_at >= %s")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = cast(list[dict[str, Any]], self._backend.fetchall(
            f"SELECT * FROM audit_alert_history {where} ORDER BY triggered_at DESC LIMIT %s",
            tuple(params),
        ))
        return [_coerce_alert_row(r) for r in rows]

    def acknowledge_alert(
        self,
        alert_id: str,
        *,
        acknowledged_by: str = "",
    ) -> bool:
        if not self._backend:
            return False
        self._backend.execute(
            """UPDATE audit_alert_history
               SET acknowledged=1, acknowledged_by=%s, acknowledged_at=%s
               WHERE alert_id=%s""",
            (acknowledged_by, time.time(), alert_id),
        )
        return True


def _coerce_rule_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a DB row into a serialisable alert-rule dict."""
    out = dict(row)
    if "enabled" in out and not isinstance(out["enabled"], bool):
        out["enabled"] = bool(out["enabled"])
    for k in ("condition", "action_config"):
        v = out.get(k)
        if isinstance(v, str):
            try:
                out[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                out[k] = {}
        elif v is None:
            out[k] = {}
    return out


def _coerce_alert_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a DB row into a serialisable alert-history dict."""
    out = dict(row)
    if "acknowledged" in out and not isinstance(out["acknowledged"], bool):
        out["acknowledged"] = bool(out["acknowledged"])
    v = out.get("metadata")
    if isinstance(v, str):
        try:
            out["metadata"] = json.loads(v)
        except (json.JSONDecodeError, TypeError):
            out["metadata"] = {}
    elif v is None:
        out["metadata"] = {}
    return out


class PgLicenseStore:
    """PostgreSQL-backed license management persistence.

    Stores issued licenses and audit logs for the License Management
    feature (PRD: license-management). Schema is auto-created on first
    use via ``CREATE TABLE IF NOT EXISTS``.

    Tables:
      - ``licenses``: one row per issued license (key + metadata)
      - ``license_audit_logs``: append-only audit trail per license
    """

    def __init__(self) -> None:
        self._backend = _get_pg_backend()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        if not self._backend:
            return
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_id TEXT PRIMARY KEY,
                customer TEXT NOT NULL,
                edition TEXT NOT NULL DEFAULT 'enterprise',
                max_users INTEGER,
                fingerprint TEXT,
                features JSONB DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'active',
                issued_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                revoked_at DOUBLE PRECISION DEFAULT NULL,
                revoked_reason TEXT DEFAULT '',
                license_key TEXT NOT NULL,
                issued_by TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at DOUBLE PRECISION DEFAULT 0,
                updated_at DOUBLE PRECISION DEFAULT 0
            )
        """)
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at)")
        self._backend.execute("""
            CREATE TABLE IF NOT EXISTS license_audit_logs (
                log_id TEXT PRIMARY KEY,
                license_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT DEFAULT '',
                timestamp DOUBLE PRECISION NOT NULL,
                detail TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                metadata JSONB DEFAULT '{}',
                FOREIGN KEY (license_id) REFERENCES licenses(license_id) ON DELETE CASCADE
            )
        """)
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_license ON license_audit_logs(license_id)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_action ON license_audit_logs(action)")
        self._backend.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_timestamp ON license_audit_logs(timestamp)")

    @property
    def available(self) -> bool:
        return self._backend is not None

    def save_license(self, data: dict[str, Any]) -> None:
        if not self._backend:
            return
        features = json.dumps(data.get("features", []))
        self._backend.execute(
            """INSERT INTO licenses
               (license_id, customer, edition, max_users, fingerprint, features, status,
                issued_at, expires_at, revoked_at, revoked_reason, license_key,
                issued_by, notes, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (license_id) DO UPDATE SET
                 customer=EXCLUDED.customer, edition=EXCLUDED.edition,
                 max_users=EXCLUDED.max_users, fingerprint=EXCLUDED.fingerprint,
                 features=EXCLUDED.features, status=EXCLUDED.status,
                 expires_at=EXCLUDED.expires_at, revoked_at=EXCLUDED.revoked_at,
                 revoked_reason=EXCLUDED.revoked_reason, license_key=EXCLUDED.license_key,
                 issued_by=EXCLUDED.issued_by, notes=EXCLUDED.notes,
                 updated_at=EXCLUDED.updated_at""",
            (data["license_id"], data["customer"], data.get("edition", "enterprise"),
             data.get("max_users"), data.get("fingerprint"), features,
             data.get("status", "active"), data["issued_at"], data["expires_at"],
             data.get("revoked_at"), data.get("revoked_reason", ""),
             data["license_key"], data.get("issued_by", ""), data.get("notes", ""),
             data.get("created_at", 0), data.get("updated_at", 0)),
        )

    def delete_license(self, license_id: str) -> bool:
        if not self._backend:
            return False
        self._backend.execute("DELETE FROM license_audit_logs WHERE license_id=%s", (license_id,))
        self._backend.execute("DELETE FROM licenses WHERE license_id=%s", (license_id,))
        return True

    def load_licenses(self, status: str = "") -> list[dict[str, Any]]:
        if not self._backend:
            return []
        if status:
            return cast(list[dict[str, Any]], self._backend.fetchall(
                "SELECT * FROM licenses WHERE status=%s ORDER BY created_at DESC",
                (status,),
            ))
        return cast(list[dict[str, Any]], self._backend.fetchall(
            "SELECT * FROM licenses ORDER BY created_at DESC",
        ))

    def load_license(self, license_id: str) -> dict[str, Any] | None:
        if not self._backend:
            return None
        return cast(dict[str, Any] | None, self._backend.fetchone(
            "SELECT * FROM licenses WHERE license_id=%s", (license_id,),
        ))

    def save_audit_log(self, event: dict[str, Any]) -> None:
        if not self._backend:
            return
        meta = json.dumps(event.get("metadata", {}))
        self._backend.execute(
            """INSERT INTO license_audit_logs
               (log_id, license_id, action, actor, timestamp, detail, ip_address, metadata)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (event["log_id"], event["license_id"], event["action"],
             event.get("actor", ""), event["timestamp"], event.get("detail", ""),
             event.get("ip_address", ""), meta),
        )

    def load_audit_logs(
        self,
        license_id: str = "",
        action: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if not self._backend:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if license_id:
            clauses.append("license_id=%s")
            params.append(license_id)
        if action:
            clauses.append("action=%s")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        return cast(list[dict[str, Any]], self._backend.fetchall(
            f"SELECT * FROM license_audit_logs {where} ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            tuple(params),
        ))
