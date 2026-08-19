"""MAOP Enterprise Notification Center.

Provides a pluggable notification subsystem with:
  - Channel abstraction (BaseChannel) + Email/Webhook/InApp implementations
  - Event bus (pub/sub) for system events
  - NotificationManager: orchestrates channels, rules, templates, delivery
  - Async delivery with retry (3 attempts) and dead-letter queue
  - Multi-tenant isolation (every record carries ``tenant_id``)
  - Encrypted storage for SMTP passwords / Webhook secrets (Fernet)

Public API::

    from maop.enterprise.notification import (
        EventBus,
        NotificationManager,
        BaseChannel,
        EmailChannel,
        WebhookChannel,
        InAppChannel,
    )

Submodules:
  - models.py     Pydantic schemas (Channel/Rule/Template/Notification/Preference)
  - channels.py   BaseChannel + Email/Webhook/InApp implementations
  - event_bus.py  EventBus pub/sub
  - manager.py    NotificationManager (orchestrator)
  - store.py      SQLite/PG persistence + Fernet encryption for secrets
"""

from __future__ import annotations

from maop.enterprise.notification.channels import (
    BaseChannel,
    EmailChannel,
    InAppChannel,
    WebhookChannel,
    get_channel_class,
    register_channel,
)
from maop.enterprise.notification.event_bus import EventBus
from maop.enterprise.notification.manager import NotificationManager
from maop.enterprise.notification.models import (
    ChannelCreate,
    ChannelResponse,
    ChannelUpdate,
    NotificationResponse,
    PreferenceResponse,
    PreferenceUpdate,
    RuleCreate,
    RuleResponse,
    RuleUpdate,
    TemplateCreate,
    TemplateResponse,
)

__all__: list[str] = [
    # Channels
    "BaseChannel",
    # Pydantic models
    "ChannelCreate",
    "ChannelResponse",
    "ChannelUpdate",
    "EmailChannel",
    # Event bus
    "EventBus",
    "InAppChannel",
    # Manager
    "NotificationManager",
    "NotificationResponse",
    "PreferenceResponse",
    "PreferenceUpdate",
    "RuleCreate",
    "RuleResponse",
    "RuleUpdate",
    "TemplateCreate",
    "TemplateResponse",
    "WebhookChannel",
    "get_channel_class",
    "register_channel",
]