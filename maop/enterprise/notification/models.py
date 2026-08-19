"""Pydantic models for the notification center.

Covers channels, rules, templates, notifications and per-user preferences.
All models are tenant-aware (``tenant_id`` field) and use ``str`` enums so
they JSON-serialise cleanly for API responses.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ── Enums ─────────────────────────────────────────────────────────


class ChannelType(str, Enum):
    """Supported channel kinds. New types are registered via ``register_channel``."""

    EMAIL = "email"
    WEBHOOK = "webhook"
    INAPP = "inapp"


class ChannelStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


class RuleStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class NotificationStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"


class NotificationLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# Canonical event types the event bus accepts. Extending this set is
# backward compatible — unknown events are still accepted by EventBus
# (it logs a debug message) but rules won't match them.
class EventType(str, Enum):
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    AGENT_ERROR = "agent_error"
    QUOTA_EXCEEDED = "quota_exceeded"
    LICENSE_EXPIRING = "license_expiring"
    AUDIT_ALERT = "audit_alert"
    SYSTEM_ERROR = "system_error"
    DAG_COMPLETED = "dag_completed"
    DAG_FAILED = "dag_failed"


# ── Channel models ────────────────────────────────────────────────


class ChannelCreate(BaseModel):
    """Request body for POST /api/notifications/channels."""

    name: str = Field(min_length=1, max_length=100)
    type: ChannelType
    config: dict[str, Any] = Field(default_factory=dict)
    description: str = Field(default="", max_length=500)
    tenant_id: str = ""
    enabled: bool = True


class ChannelUpdate(BaseModel):
    """Request body for PUT /api/notifications/channels/{channel_id}.

    All fields optional — only supplied fields are updated.
    """

    name: str | None = Field(default=None, min_length=1, max_length=100)
    config: dict[str, Any] | None = None
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class ChannelResponse(BaseModel):
    """Channel as returned by GET endpoints.

    ``config`` is returned with secrets masked (e.g. ``password: "***"``).
    """

    channel_id: str
    name: str
    type: ChannelType
    config: dict[str, Any]
    description: str = ""
    tenant_id: str = ""
    enabled: bool = True
    status: ChannelStatus = ChannelStatus.ACTIVE
    created_at: float = 0.0
    updated_at: float = 0.0
    last_error: str = ""


# ── Rule models ───────────────────────────────────────────────────


class RuleCreate(BaseModel):
    """Request body for POST /api/notifications/rules.

    A rule binds an event type to one or more channels with an optional
    Jinja2-free template. ``filter`` is a JSON dict matched against the
    event payload (subset match — all key/values in ``filter`` must be
    present and equal in the event payload).
    """

    name: str = Field(min_length=1, max_length=100)
    event_type: str
    channel_ids: list[str] = Field(default_factory=list)
    template_id: str = ""
    filter: dict[str, Any] = Field(default_factory=dict)
    level: NotificationLevel = NotificationLevel.INFO
    tenant_id: str = ""
    enabled: bool = True
    description: str = Field(default="", max_length=500)


class RuleUpdate(BaseModel):
    """Request body for PUT /api/notifications/rules/{rule_id}."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    event_type: str | None = None
    channel_ids: list[str] | None = None
    template_id: str | None = None
    filter: dict[str, Any] | None = None
    level: NotificationLevel | None = None
    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=500)


class RuleResponse(BaseModel):
    """Rule as returned by GET endpoints."""

    rule_id: str
    name: str
    event_type: str
    channel_ids: list[str] = Field(default_factory=list)
    template_id: str = ""
    filter: dict[str, Any] = Field(default_factory=dict)
    level: NotificationLevel = NotificationLevel.INFO
    tenant_id: str = ""
    enabled: bool = True
    status: RuleStatus = RuleStatus.ACTIVE
    description: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    trigger_count: int = 0
    last_triggered_at: float = 0.0


# ── Template models ───────────────────────────────────────────────


class TemplateCreate(BaseModel):
    """Request body for POST /api/notifications/templates.

    Templates use ``{placeholder}`` style substitution (``str.format_map``).
    No Jinja2 dependency. ``subject`` is used only for email channels.
    """

    name: str = Field(min_length=1, max_length=100)
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1)
    tenant_id: str = ""
    description: str = Field(default="", max_length=500)


class TemplateResponse(BaseModel):
    """Template as returned by GET endpoints."""

    template_id: str
    name: str
    subject: str = ""
    body: str = ""
    tenant_id: str = ""
    description: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0


# ── Notification models ───────────────────────────────────────────


class NotificationResponse(BaseModel):
    """A delivered (or pending) notification record."""

    notification_id: str
    tenant_id: str = ""
    user_id: str = ""
    channel_id: str = ""
    channel_type: ChannelType = ChannelType.INAPP
    level: NotificationLevel = NotificationLevel.INFO
    title: str = ""
    body: str = ""
    status: NotificationStatus = NotificationStatus.PENDING
    event_type: str = ""
    event_payload: dict[str, Any] = Field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    error: str = ""
    created_at: float = 0.0
    sent_at: float = 0.0
    read_at: float = 0.0  # 0 = unread (InApp only)


# ── Preference models ─────────────────────────────────────────────


class PreferenceUpdate(BaseModel):
    """Per-user notification preferences.

    ``channel_enabled`` maps ``channel_type`` → on/off.
    ``event_level_min`` maps ``event_type`` → minimum level to deliver
    (e.g. ``{"task_failed": "warning"}`` means only warning+ for task_failed).
    """

    channel_enabled: dict[str, bool] | None = None
    event_level_min: dict[str, str] | None = None
    quiet_hours_start: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_end: int | None = Field(default=None, ge=0, le=23)


class PreferenceResponse(BaseModel):
    """User preferences as returned by GET endpoints."""

    user_id: str
    tenant_id: str = ""
    channel_enabled: dict[str, bool] = Field(default_factory=dict)
    event_level_min: dict[str, str] = Field(default_factory=dict)
    quiet_hours_start: int = -1  # -1 = not set
    quiet_hours_end: int = -1
    updated_at: float = 0.0


# ── Event payload ─────────────────────────────────────────────────


class EventPayload(BaseModel):
    """Structured event published to EventBus.

    ``event_type`` is a free-form string (canonical values in ``EventType``).
    ``payload`` is the event-specific data dict. ``tenant_id`` scopes the
    event; rules with a different tenant won't match.
    """

    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = ""
    timestamp: float = 0.0