"""MAOP Audit Enhancement — Advanced filtering, statistics, alerting engine.

Implements the audit-enhancement PRD:
  - Pydantic request/response models (AuditEventQuery, AuditAlertRuleCreate,
    AuditStatsResponse, etc.)
  - AuditAlertEngine: rule-based alert evaluation over audit events
    (threshold / pattern / anomaly condition types), with in-memory rule
    store + optional PostgreSQL persistence via PgAuditAlertStore.
  - AuditAlertBroadcaster: pluggable async hook for WebSocket push so the
    router layer can wire it to the dashboard's existing WS pool without
    importing FastAPI here.

Design notes:
  - The engine is edition-agnostic. It works in personal edition (in-memory
    rules + alerts) and enterprise edition (PgAuditAlertStore persistence).
  - All public methods are synchronous; the broadcaster callback is the
    only async surface so the engine can be unit-tested without an event
    loop.
  - Rule condition schema (stored as JSON in ``condition`` field):
      threshold: {"metric": "count", "window_s": 300, "op": ">=", "value": 10,
                  "filter": {"action": "login", "result": "failure"}}
      pattern:   {"field": "actor", "regex": "^anonymous$"}
      anomaly:   {"field": "action", "min_occurrences": 5, "window_s": 60}
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, has_feature
from maop.enterprise.audit import AuditEvent, AuditSeverity

logger = logging.getLogger(__name__)

#: 同一规则最小告警间隔（秒）—— 防止阈值规则持续命中时的告警风暴
ALERT_MIN_INTERVAL_S: float = 60.0


# ── Enums ─────────────────────────────────────────────────────────


class AlertConditionType(str, Enum):
    THRESHOLD = "threshold"
    PATTERN = "pattern"
    ANOMALY = "anomaly"


class AlertAction(str, Enum):
    NOTIFY = "notify"
    WEBHOOK = "webhook"
    EMAIL = "email"
    LOG = "log"


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# ── Pydantic models ───────────────────────────────────────────────


class AuditEventQuery(BaseModel):
    """Advanced query parameters for /api/audit/events/advanced."""

    tenant_id: str = ""
    actions: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    risk_levels: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    results: list[str] = Field(default_factory=list)
    since: float = 0.0
    until: float = 0.0
    search: str = ""  # substring match on detail/resource/actor
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)
    sort: str = "timestamp_desc"  # timestamp_desc | timestamp_asc | severity_desc


class AuditAlertRuleCreate(BaseModel):
    """Request body for POST /api/audit/alert/rules."""

    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    enabled: bool = True
    condition_type: AlertConditionType = AlertConditionType.THRESHOLD
    condition: dict[str, Any] = Field(default_factory=dict)
    action: AlertAction = AlertAction.NOTIFY
    action_config: dict[str, Any] = Field(default_factory=dict)
    severity: AlertSeverity = AlertSeverity.WARNING
    tenant_id: str = ""


class AuditAlertRuleUpdate(BaseModel):
    """Request body for PUT /api/audit/alert/rules/{rule_id}.

    All fields optional — only supplied fields are updated.
    """

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    condition_type: AlertConditionType | None = None
    condition: dict[str, Any] | None = None
    action: AlertAction | None = None
    action_config: dict[str, Any] | None = None
    severity: AlertSeverity | None = None


class AuditAlertRule(BaseModel):
    """Full alert rule model (stored + returned)."""

    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    condition_type: AlertConditionType = AlertConditionType.THRESHOLD
    condition: dict[str, Any] = Field(default_factory=dict)
    action: AlertAction = AlertAction.NOTIFY
    action_config: dict[str, Any] = Field(default_factory=dict)
    severity: AlertSeverity = AlertSeverity.WARNING
    tenant_id: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    created_by: str = ""


class AuditAlert(BaseModel):
    """A triggered alert record (in audit_alert_history)."""

    alert_id: str
    rule_id: str
    triggered_at: float
    event_id: str = ""
    severity: str = "warning"
    message: str = ""
    acknowledged: bool = False
    acknowledged_by: str = ""
    acknowledged_at: float | None = None
    tenant_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditStatsResponse(BaseModel):
    """Response model for /api/audit/stats."""

    total_events: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_actor: dict[str, int] = Field(default_factory=dict)
    by_result: dict[str, int] = Field(default_factory=dict)
    critical_count: int = 0
    hours: int = 24
    top_actors: list[dict[str, Any]] = Field(default_factory=list)
    top_actions: list[dict[str, Any]] = Field(default_factory=list)


class AuditTimelinePoint(BaseModel):
    """One bucket in a timeline series."""

    ts: float
    count: int
    severity_breakdown: dict[str, int] = Field(default_factory=dict)


class AuditHeatmapCell(BaseModel):
    """One cell in a day×hour heatmap."""

    day: int  # 0=Mon .. 6=Sun
    hour: int  # 0..23
    count: int = 0
    critical_count: int = 0


# ── Alert engine ──────────────────────────────────────────────────


# Type alias for the async broadcaster callback. The engine calls it
# with the alert dict; the router layer wires it to the WS pool.
AlertBroadcaster = Callable[[dict[str, Any]], Any]


class AuditAlertEngine:
    """Rule-based alert engine over audit events.

    Features:
      - In-memory rule store + optional PG persistence (PgAuditAlertStore).
      - In-memory alert history + optional PG persistence.
      - Three condition types: threshold, pattern, anomaly.
      - Sliding-window counters for threshold/anomaly evaluation.
      - Pluggable async broadcaster for real-time WebSocket push.
      - Event-evaluation API: ``evaluate_event(event)`` returns list of
        triggered alerts (and persists + broadcasts them).
      - Bulk-evaluation API: ``evaluate_events(events)`` for backfill.

    Thread-safety: the engine is single-threaded (FastAPI async event
    loop). Callers must not share an instance across threads.
    """

    def __init__(
        self,
        *,
        broadcaster: AlertBroadcaster | None = None,
        pg_store: Any = None,
    ) -> None:
        self._rules: dict[str, AuditAlertRule] = {}
        self._alerts: deque[AuditAlert] = deque(maxlen=10000)
        self._broadcaster = broadcaster
        self._pg: Any = None
        if pg_store is not None:
            self._pg = pg_store
        elif has_feature(FeatureFlag.AUDIT_LOG):
            try:
                from maop.enterprise.pg_persist import PgAuditAlertStore
                store = PgAuditAlertStore()
                if store.available:
                    self._pg = store
            except Exception as exc:
                logger.debug("PgAuditAlertStore unavailable: %s", exc)
        # Sliding-window state for threshold/anomaly rules.
        # _window[rule_id] = deque[(timestamp, event_id)]
        self._window: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        # P0 修复：告警去重 —— 同一规则在窗口内只生成一条告警，防止
        # 阈值规则在 count 持续达标时对每个后续事件都触发（告警风暴）。
        # _last_alert_ts[rule_id] = 上次告警时间戳
        self._last_alert_ts: dict[str, float] = {}
        # Load persisted rules on init.
        self._load_rules_from_pg()

    # ── Rule store ────────────────────────────────────────────────
    def _load_rules_from_pg(self) -> None:
        if not self._pg:
            return
        try:
            for row in self._pg.load_rules():
                rule = AuditAlertRule(**row)
                self._rules[rule.rule_id] = rule
        except Exception as exc:
            logger.warning("Failed to load alert rules from PG: %s", exc)

    def list_rules(self, *, tenant_id: str = "", enabled_only: bool = False) -> list[AuditAlertRule]:
        result = list(self._rules.values())
        if tenant_id:
            result = [r for r in result if r.tenant_id == tenant_id or r.tenant_id == ""]
        if enabled_only:
            result = [r for r in result if r.enabled]
        return sorted(result, key=lambda r: r.created_at, reverse=True)

    def get_rule(self, rule_id: str) -> AuditAlertRule | None:
        return self._rules.get(rule_id)

    def create_rule(
        self,
        create: AuditAlertRuleCreate,
        *,
        created_by: str = "",
    ) -> AuditAlertRule:
        now = time.time()
        rule = AuditAlertRule(
            rule_id=f"rule_{uuid.uuid4().hex[:12]}",
            name=create.name,
            description=create.description,
            enabled=create.enabled,
            condition_type=create.condition_type,
            condition=create.condition,
            action=create.action,
            action_config=create.action_config,
            severity=create.severity,
            tenant_id=create.tenant_id,
            created_at=now,
            updated_at=now,
            created_by=created_by,
        )
        self._rules[rule.rule_id] = rule
        self._persist_rule(rule)
        return rule

    def update_rule(self, rule_id: str, update: AuditAlertRuleUpdate) -> AuditAlertRule | None:
        rule = self._rules.get(rule_id)
        if rule is None:
            return None
        changed = False
        for field_name in (
            "name", "description", "enabled", "condition_type", "condition",
            "action", "action_config", "severity",
        ):
            value = getattr(update, field_name)
            if value is not None:
                setattr(rule, field_name, value)
                changed = True
        if changed:
            rule.updated_at = time.time()
            self._persist_rule(rule)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id not in self._rules:
            return False
        del self._rules[rule_id]
        self._window.pop(rule_id, None)
        if self._pg:
            try:
                self._pg.delete_rule(rule_id)
            except Exception as exc:
                logger.warning("PG delete_rule failed: %s", exc)
        return True

    def _persist_rule(self, rule: AuditAlertRule) -> None:
        if not self._pg:
            return
        try:
            self._pg.save_rule(rule.model_dump())
        except Exception as exc:
            logger.warning("PG save_rule failed: %s", exc)

    # ── Alert history ─────────────────────────────────────────────
    def list_alerts(
        self,
        *,
        rule_id: str = "",
        tenant_id: str = "",
        acknowledged: bool | None = None,
        since: float = 0.0,
        limit: int = 100,
    ) -> list[AuditAlert]:
        result = list(self._alerts)
        if rule_id:
            result = [a for a in result if a.rule_id == rule_id]
        if tenant_id:
            result = [a for a in result if a.tenant_id == tenant_id]
        if acknowledged is not None:
            result = [a for a in result if a.acknowledged == acknowledged]
        if since:
            result = [a for a in result if a.triggered_at >= since]
        result.sort(key=lambda a: a.triggered_at, reverse=True)
        return result[:limit]

    def acknowledge_alert(
        self,
        alert_id: str,
        *,
        acknowledged_by: str = "",
    ) -> AuditAlert | None:
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = time.time()
                if self._pg:
                    try:
                        self._pg.acknowledge_alert(alert_id, acknowledged_by=acknowledged_by)
                    except Exception as exc:
                        logger.warning("PG acknowledge_alert failed: %s", exc)
                return alert
        return None

    # ── Evaluation ────────────────────────────────────────────────
    def evaluate_event(self, event: AuditEvent) -> list[AuditAlert]:
        """Evaluate all enabled rules against a single event.

        Returns the list of triggered alerts (possibly empty). Triggered
        alerts are persisted to history and broadcast (if a broadcaster
        is wired).
        """
        triggered: list[AuditAlert] = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            if rule.tenant_id and event.tenant_id and rule.tenant_id != event.tenant_id:
                continue
            if self._matches(rule, event):
                alert = self._build_alert(rule, event)
                triggered.append(alert)
                self._record_alert(alert)
        return triggered

    def evaluate_events(self, events: Iterable[AuditEvent]) -> list[AuditAlert]:
        """Bulk-evaluate rules against a stream of events."""
        all_triggered: list[AuditAlert] = []
        for event in events:
            all_triggered.extend(self.evaluate_event(event))
        return all_triggered

    def _matches(self, rule: AuditAlertRule, event: AuditEvent) -> bool:
        try:
            if rule.condition_type == AlertConditionType.THRESHOLD:
                return self._matches_threshold(rule, event)
            if rule.condition_type == AlertConditionType.PATTERN:
                return self._matches_pattern(rule, event)
            if rule.condition_type == AlertConditionType.ANOMALY:
                return self._matches_anomaly(rule, event)
        except Exception as exc:
            logger.warning("Rule %s evaluation error: %s", rule.rule_id, exc)
        return False

    def _matches_threshold(self, rule: AuditAlertRule, event: AuditEvent) -> bool:
        cond = rule.condition
        window_s = float(cond.get("window_s", 300))
        threshold = int(cond.get("value", 1))
        op = cond.get("op", ">=")
        event_filter = cond.get("filter", {}) or {}
        # First: does this event match the filter?
        if not _event_matches_filter(event, event_filter):
            return False
        # Track in sliding window.
        buf = self._window[rule.rule_id]
        now = event.timestamp
        buf.append((now, event.event_id))
        # Evict expired entries.
        cutoff = now - window_s
        while buf and buf[0][0] < cutoff:
            buf.popleft()
        count = len(buf)
        return _apply_op(count, op, threshold)

    def _matches_pattern(self, rule: AuditAlertRule, event: AuditEvent) -> bool:
        cond = rule.condition
        field_name = cond.get("field", "detail")
        regex_str = cond.get("regex", "")
        if not regex_str:
            return False
        value = _get_event_field(event, field_name)
        if value is None:
            return False
        try:
            return re.search(regex_str, str(value)) is not None
        except re.error:
            return False

    def _matches_anomaly(self, rule: AuditAlertRule, event: AuditEvent) -> bool:
        cond = rule.condition
        field_name = cond.get("field", "action")
        window_s = float(cond.get("window_s", 60))
        min_occurrences = int(cond.get("min_occurrences", 5))
        value = _get_event_field(event, field_name)
        if value is None:
            return False
        key = f"{rule.rule_id}:{field_name}:{value}"
        buf = self._window[key]
        now = event.timestamp
        buf.append((now, event.event_id))
        cutoff = now - window_s
        while buf and buf[0][0] < cutoff:
            buf.popleft()
        return len(buf) >= min_occurrences

    def _build_alert(self, rule: AuditAlertRule, event: AuditEvent) -> AuditAlert:
        return AuditAlert(
            alert_id=f"alert_{uuid.uuid4().hex[:12]}",
            rule_id=rule.rule_id,
            triggered_at=time.time(),
            event_id=event.event_id,
            severity=rule.severity.value,
            message=f"Rule '{rule.name}' triggered by event {event.event_id} (action={event.action.value})",
            tenant_id=event.tenant_id,
            metadata={
                "rule_name": rule.name,
                "condition_type": rule.condition_type.value,
                "event_action": event.action.value,
                "event_actor": event.actor,
            },
        )

    def _record_alert(self, alert: AuditAlert) -> None:
        # P0 修复：去重 —— 同一规则在 60s 内只记录/广播一条告警，
        # 防止阈值规则持续达标时的告警风暴（规则命中 ≠ 每条都发）。
        now = time.time()
        last = self._last_alert_ts.get(alert.rule_id, 0.0)
        if now - last < ALERT_MIN_INTERVAL_S:
            return
        self._last_alert_ts[alert.rule_id] = now
        self._alerts.append(alert)
        if self._pg:
            try:
                self._pg.save_alert(alert.model_dump())
            except Exception as exc:
                logger.warning("PG save_alert failed: %s", exc)
        if self._broadcaster is not None:
            try:
                self._broadcaster(alert.model_dump())
            except Exception as exc:
                logger.warning("Alert broadcaster failed: %s", exc)


# ── Helpers ───────────────────────────────────────────────────────


def _event_matches_filter(event: AuditEvent, filt: dict[str, Any]) -> bool:
    """Return True if event matches all key=value constraints in ``filt``."""
    for key, expected in filt.items():
        actual = _get_event_field(event, key)
        if actual is None:
            return False
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _get_event_field(event: AuditEvent, field_name: str) -> Any:
    """Get a field from an AuditEvent by name, with dotted-path support."""
    if "." in field_name:
        # dotted path into metadata, e.g. "metadata.ip"
        head, _, tail = field_name.partition(".")
        if head == "metadata":
            return event.metadata.get(tail)
        return None
    return getattr(event, field_name, None)


def _apply_op(left: int, op: str, right: int) -> bool:
    if op == ">=":
        return left >= right
    if op == ">":
        return left > right
    if op == "<=":
        return left <= right
    if op == "<":
        return left < right
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    return False


# ── Statistics helpers (used by router) ───────────────────────────


def compute_stats(events: list[AuditEvent], *, hours: int = 24) -> AuditStatsResponse:
    """Compute aggregate statistics over a list of events."""
    by_action: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_risk: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    by_actor: dict[str, int] = defaultdict(int)
    by_result: dict[str, int] = defaultdict(int)
    critical = 0
    for e in events:
        by_action[e.action.value] += 1
        by_severity[e.severity.value] += 1
        by_risk[e.risk_level.value] += 1
        cat = e.category or "uncategorised"
        by_category[cat] += 1
        if e.actor:
            by_actor[e.actor] += 1
        if e.result:
            by_result[e.result] += 1
        if e.severity == AuditSeverity.CRITICAL:
            critical += 1

    def _top(d: dict[str, int], n: int = 10) -> list[dict[str, Any]]:
        return [{"key": k, "count": v} for k, v in sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]]

    return AuditStatsResponse(
        total_events=len(events),
        by_action=dict(by_action),
        by_severity=dict(by_severity),
        by_risk_level=dict(by_risk),
        by_category=dict(by_category),
        by_actor=dict(by_actor),
        by_result=dict(by_result),
        critical_count=critical,
        hours=hours,
        top_actors=_top(by_actor),
        top_actions=_top(by_action),
    )


def compute_timeline(
    events: list[AuditEvent],
    *,
    bucket_s: int = 3600,
    since: float = 0.0,
    until: float = 0.0,
) -> list[AuditTimelinePoint]:
    """Bucket events into time windows of ``bucket_s`` seconds."""
    if not events:
        return []
    if since == 0.0:
        since = min(e.timestamp for e in events)
    if until == 0.0:
        until = max(e.timestamp for e in events)
    if until <= since:
        return []
    buckets: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in events:
        if e.timestamp < since or e.timestamp > until:
            continue
        bucket_idx = int((e.timestamp - since) // bucket_s)
        buckets[bucket_idx]["count"] += 1
        buckets[bucket_idx][e.severity.value] += 1
    points: list[AuditTimelinePoint] = []
    n_buckets = int((until - since) // bucket_s) + 1
    for i in range(n_buckets):
        ts = since + i * bucket_s
        b = buckets.get(i, {})
        count = b.pop("count", 0)
        points.append(AuditTimelinePoint(ts=ts, count=count, severity_breakdown=dict(b)))
    return points


def compute_heatmap(events: list[AuditEvent]) -> list[AuditHeatmapCell]:
    """Compute a 7×24 day×hour heatmap of event counts."""
    grid: dict[tuple[int, int], dict[str, int]] = defaultdict(lambda: {"count": 0, "critical": 0})
    for e in events:
        # Use UTC to avoid tz-dependent test failures; dashboard can shift.
        import datetime as _dt
        try:
            dt = _dt.datetime.fromtimestamp(e.timestamp, _dt.UTC)
        except AttributeError:  # Python < 3.11
            dt = _dt.datetime.utcfromtimestamp(e.timestamp)  # noqa: DTZ004
        day = dt.weekday()
        hour = dt.hour
        grid[(day, hour)]["count"] += 1
        if e.severity == AuditSeverity.CRITICAL:
            grid[(day, hour)]["critical"] += 1
    cells: list[AuditHeatmapCell] = []
    for day in range(7):
        for hour in range(24):
            cell = grid.get((day, hour), {"count": 0, "critical": 0})
            cells.append(AuditHeatmapCell(
                day=day, hour=hour,
                count=cell["count"], critical_count=cell["critical"],
            ))
    return cells


def filter_events(events: list[AuditEvent], query: AuditEventQuery) -> tuple[list[AuditEvent], int]:
    """Apply advanced filtering to a list of events.

    Returns (filtered_page, total_matching).
    """
    result = events
    if query.tenant_id:
        result = [e for e in result if e.tenant_id == query.tenant_id]
    if query.actions:
        result = [e for e in result if e.action.value in query.actions]
    if query.severities:
        result = [e for e in result if e.severity.value in query.severities]
    if query.risk_levels:
        result = [e for e in result if e.risk_level.value in query.risk_levels]
    if query.categories:
        result = [e for e in result if e.category in query.categories]
    if query.tags:
        result = [e for e in result if all(t in e.tags for t in query.tags)]
    if query.actors:
        result = [e for e in result if e.actor in query.actors]
    if query.resources:
        result = [e for e in result if e.resource in query.resources]
    if query.results:
        result = [e for e in result if e.result in query.results]
    if query.since:
        result = [e for e in result if e.timestamp >= query.since]
    if query.until:
        result = [e for e in result if e.timestamp <= query.until]
    if query.search:
        needle = query.search.lower()
        result = [
            e for e in result
            if needle in e.detail.lower()
            or needle in e.resource.lower()
            or needle in e.actor.lower()
        ]
    total = len(result)
    # Sort
    if query.sort == "timestamp_asc":
        result = sorted(result, key=lambda e: e.timestamp)
    elif query.sort == "severity_desc":
        severity_order = {AuditSeverity.INFO: 0, AuditSeverity.WARNING: 1, AuditSeverity.CRITICAL: 2}
        result = sorted(result, key=lambda e: severity_order.get(e.severity, 0), reverse=True)
    else:  # timestamp_desc default
        result = sorted(result, key=lambda e: e.timestamp, reverse=True)
    page = result[query.offset: query.offset + query.limit]
    return page, total


def export_events_csv(events: list[AuditEvent]) -> str:
    """Serialise events to a CSV string (header row + data rows)."""
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "event_id", "timestamp", "action", "severity", "risk_level",
        "category", "actor", "tenant_id", "resource", "result",
        "ip_address", "user_agent", "detail", "tags",
    ])
    for e in events:
        writer.writerow([
            e.event_id, e.timestamp, e.action.value, e.severity.value,
            e.risk_level.value, e.category, e.actor, e.tenant_id,
            e.resource, e.result, e.ip_address, e.user_agent, e.detail,
            "|".join(e.tags),
        ])
    return output.getvalue()


def export_events_json(events: list[AuditEvent]) -> str:
    """Serialise events to a JSON array string."""
    import json
    return json.dumps([e.model_dump(mode="json") for e in events], default=str)