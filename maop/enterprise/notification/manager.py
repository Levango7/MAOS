"""NotificationManager — orchestrates channels, rules, templates and delivery.

Responsibilities:
  - Channel CRUD (delegates persistence to NotificationStore)
  - Rule CRUD
  - Template CRUD
  - Preference CRUD
  - Notification list / mark-read / delete
  - Event-driven delivery: subscribes to EventBus, matches rules,
    renders templates, dispatches to channels (async, with retry)
  - Direct delivery: ``send_notification`` bypasses rules and sends
    immediately to a specified channel
  - Dead-letter queue: notifications that exhaust retries are marked
    ``dead_letter`` and retrievable via ``list_dead_letters``
  - WebSocket broadcaster hook: when an InApp notification is created,
    the manager invokes the registered broadcaster so the dashboard can
    push it to connected clients in real time

Delivery flow (per event):
  1. EventBus.publish(event)
  2. Manager._on_event(event)  (subscribed in __init__)
  3. For each matching rule (same event_type, tenant, filter passes):
     a. For each channel_id in rule.channel_ids:
        i.   Render title/body from template (or default)
        ii.  Create notification record (status=pending)
        iii. asyncio.create_task(_deliver(notification, channel))
  4. _deliver:
     a. channel.send(...) (in thread — sync channels)
     b. On success: status=sent
     c. On failure: retry_count++, status=retrying, re-queue with backoff
     d. After max_retries: status=dead_letter
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from maop.enterprise.notification.channels import BaseChannel, get_channel_class
from maop.enterprise.notification.event_bus import EventBus
from maop.enterprise.notification.models import (
    ChannelCreate,
    ChannelResponse,
    ChannelStatus,
    ChannelType,
    ChannelUpdate,
    NotificationLevel,
    NotificationResponse,
    NotificationStatus,
    PreferenceResponse,
    PreferenceUpdate,
    RuleCreate,
    RuleResponse,
    RuleStatus,
    RuleUpdate,
    TemplateCreate,
    TemplateResponse,
)
from maop.enterprise.notification.store import (
    NotificationStore,
    _mask_config,
    get_store,
)

logger = logging.getLogger(__name__)


# Broadcaster type: async callable that receives a notification dict and
# pushes it to connected WebSocket clients. The dashboard server registers
# its ``_ws_broadcast`` function here.
Broadcaster = Any  # Callable[[dict[str, Any]], Awaitable[None]]


class NotificationManager:
    """Central orchestrator for the notification subsystem.

    A single instance is intended to live for the lifetime of the process
    (the router module holds a module-level singleton). All public methods
    are safe to call from async contexts; sync CRUD methods are wrapped
    with ``asyncio.to_thread`` internally where they touch the DB.
    """

    def __init__(
        self,
        *,
        store: NotificationStore | None = None,
        event_bus: EventBus | None = None,
        max_retries: int = 3,
        retry_backoff_s: float = 2.0,
    ) -> None:
        self.store = store or get_store()
        self.event_bus = event_bus or EventBus()
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self._broadcaster: Broadcaster | None = None
        self._channel_cache: dict[str, BaseChannel] = {}
        # 后台投递任务集合：持有强引用防止任务在事件循环运行前被 GC 回收
        # （asyncio 仅对 pending task 持弱引用），任务完成后自动移除。
        self._delivery_tasks: set = set()
        # Subscribe the manager to the event bus for rule-driven delivery.
        self.event_bus.subscribe("*", self._on_event)

    # ── Broadcaster hook ─────────────────────────────────────────

    def set_broadcaster(self, broadcaster: Broadcaster) -> None:
        """Register an async callable for WebSocket push.

        Called with a notification dict whenever an InApp notification is
        created. The dashboard server wires this to its ``_ws_broadcast``.
        """
        self._broadcaster = broadcaster

    async def _broadcast(self, notif: dict[str, Any]) -> None:
        if self._broadcaster is None:
            return
        try:
            result = self._broadcaster(notif)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            logger.warning("[notification.manager] broadcaster failed: %s", exc)

    # ── Channel CRUD ─────────────────────────────────────────────

    def create_channel(self, body: ChannelCreate) -> ChannelResponse:
        now = time.time()
        channel_id = self.store.new_id("ch")
        rec = {
            "channel_id": channel_id,
            "name": body.name,
            "type": body.type.value,
            "config": body.config,
            "description": body.description,
            "tenant_id": body.tenant_id,
            "enabled": body.enabled,
            "status": ChannelStatus.ACTIVE.value,
            "last_error": "",
            "created_at": now,
            "updated_at": now,
        }
        self.store.save_channel(rec)
        return self._channel_response(rec)

    def update_channel(self, channel_id: str, body: ChannelUpdate) -> ChannelResponse | None:
        existing = self.store.get_channel(channel_id)
        if existing is None:
            return None
        if body.name is not None:
            existing["name"] = body.name
        if body.config is not None:
            existing["config"] = body.config
        if body.description is not None:
            existing["description"] = body.description
        if body.enabled is not None:
            existing["enabled"] = body.enabled
        existing["updated_at"] = time.time()
        self.store.save_channel(existing)
        self._channel_cache.pop(channel_id, None)
        return self._channel_response(existing)

    def get_channel(self, channel_id: str) -> ChannelResponse | None:
        rec = self.store.get_channel(channel_id)
        return self._channel_response(rec) if rec else None

    def list_channels(self, tenant_id: str = "") -> list[ChannelResponse]:
        return [self._channel_response(r) for r in self.store.list_channels(tenant_id)]

    def delete_channel(self, channel_id: str) -> bool:
        self._channel_cache.pop(channel_id, None)
        return self.store.delete_channel(channel_id)

    def _channel_response(self, rec: dict[str, Any]) -> ChannelResponse:
        return ChannelResponse(
            channel_id=rec["channel_id"],
            name=rec["name"],
            type=ChannelType(rec["type"]),
            config=_mask_config(rec.get("config", {})),
            description=rec.get("description", ""),
            tenant_id=rec.get("tenant_id", ""),
            enabled=rec.get("enabled", True),
            status=ChannelStatus(rec.get("status", "active")),
            created_at=rec.get("created_at", 0.0),
            updated_at=rec.get("updated_at", 0.0),
            last_error=rec.get("last_error", ""),
        )

    def _instantiate_channel(self, channel_id: str) -> BaseChannel | None:
        if channel_id in self._channel_cache:
            return self._channel_cache[channel_id]
        rec = self.store.get_channel(channel_id)
        if rec is None or not rec.get("enabled", True):
            return None
        try:
            cls = get_channel_class(rec["type"])
        except KeyError:
            logger.warning("[notification.manager] unknown channel type: %s", rec["type"])
            return None
        ch = cls(
            channel_id=rec["channel_id"],
            name=rec["name"],
            tenant_id=rec.get("tenant_id", ""),
            config=rec.get("config", {}),
        )
        self._channel_cache[channel_id] = ch
        return ch

    # ── Rule CRUD ────────────────────────────────────────────────

    def create_rule(self, body: RuleCreate) -> RuleResponse:
        now = time.time()
        rule_id = self.store.new_id("rule")
        rec = {
            "rule_id": rule_id,
            "name": body.name,
            "event_type": body.event_type,
            "channel_ids": body.channel_ids,
            "template_id": body.template_id,
            "filter": body.filter,
            "level": body.level.value,
            "tenant_id": body.tenant_id,
            "enabled": body.enabled,
            "status": RuleStatus.ACTIVE.value,
            "description": body.description,
            "trigger_count": 0,
            "last_triggered_at": 0.0,
            "created_at": now,
            "updated_at": now,
        }
        self.store.save_rule(rec)
        return self._rule_response(rec)

    def update_rule(self, rule_id: str, body: RuleUpdate) -> RuleResponse | None:
        existing = self.store.get_rule(rule_id)
        if existing is None:
            return None
        if body.name is not None:
            existing["name"] = body.name
        if body.event_type is not None:
            existing["event_type"] = body.event_type
        if body.channel_ids is not None:
            existing["channel_ids"] = body.channel_ids
        if body.template_id is not None:
            existing["template_id"] = body.template_id
        if body.filter is not None:
            existing["filter"] = body.filter
        if body.level is not None:
            existing["level"] = body.level.value
        if body.enabled is not None:
            existing["enabled"] = body.enabled
        if body.description is not None:
            existing["description"] = body.description
        existing["updated_at"] = time.time()
        self.store.save_rule(existing)
        return self._rule_response(existing)

    def get_rule(self, rule_id: str) -> RuleResponse | None:
        rec = self.store.get_rule(rule_id)
        return self._rule_response(rec) if rec else None

    def list_rules(self, tenant_id: str = "", event_type: str = "") -> list[RuleResponse]:
        return [
            self._rule_response(r)
            for r in self.store.list_rules(tenant_id=tenant_id, event_type=event_type)
        ]

    def delete_rule(self, rule_id: str) -> bool:
        return self.store.delete_rule(rule_id)

    def _rule_response(self, rec: dict[str, Any]) -> RuleResponse:
        return RuleResponse(
            rule_id=rec["rule_id"],
            name=rec["name"],
            event_type=rec["event_type"],
            channel_ids=rec.get("channel_ids", []),
            template_id=rec.get("template_id", ""),
            filter=rec.get("filter", {}),
            level=NotificationLevel(rec.get("level", "info")),
            tenant_id=rec.get("tenant_id", ""),
            enabled=rec.get("enabled", True),
            status=RuleStatus(rec.get("status", "active")),
            description=rec.get("description", ""),
            created_at=rec.get("created_at", 0.0),
            updated_at=rec.get("updated_at", 0.0),
            trigger_count=rec.get("trigger_count", 0),
            last_triggered_at=rec.get("last_triggered_at", 0.0),
        )

    # ── Template CRUD ────────────────────────────────────────────

    def create_template(self, body: TemplateCreate) -> TemplateResponse:
        now = time.time()
        template_id = self.store.new_id("tpl")
        rec = {
            "template_id": template_id,
            "name": body.name,
            "subject": body.subject,
            "body": body.body,
            "tenant_id": body.tenant_id,
            "description": body.description,
            "created_at": now,
            "updated_at": now,
        }
        self.store.save_template(rec)
        return self._template_response(rec)

    def get_template(self, template_id: str) -> TemplateResponse | None:
        rec = self.store.get_template(template_id)
        return self._template_response(rec) if rec else None

    def list_templates(self, tenant_id: str = "") -> list[TemplateResponse]:
        return [self._template_response(r) for r in self.store.list_templates(tenant_id)]

    def delete_template(self, template_id: str) -> bool:
        return self.store.delete_template(template_id)

    def _template_response(self, rec: dict[str, Any]) -> TemplateResponse:
        return TemplateResponse(
            template_id=rec["template_id"],
            name=rec["name"],
            subject=rec.get("subject", ""),
            body=rec.get("body", ""),
            tenant_id=rec.get("tenant_id", ""),
            description=rec.get("description", ""),
            created_at=rec.get("created_at", 0.0),
            updated_at=rec.get("updated_at", 0.0),
        )

    # ── Preference CRUD ──────────────────────────────────────────

    def update_preference(self, user_id: str, body: PreferenceUpdate, tenant_id: str = "") -> PreferenceResponse:
        existing = self.store.get_preference(user_id) or {
            "user_id": user_id,
            "tenant_id": tenant_id,
            "channel_enabled": {},
            "event_level_min": {},
            "quiet_hours_start": -1,
            "quiet_hours_end": -1,
        }
        if body.channel_enabled is not None:
            existing["channel_enabled"] = body.channel_enabled
        if body.event_level_min is not None:
            existing["event_level_min"] = body.event_level_min
        if body.quiet_hours_start is not None:
            existing["quiet_hours_start"] = body.quiet_hours_start
        if body.quiet_hours_end is not None:
            existing["quiet_hours_end"] = body.quiet_hours_end
        existing["tenant_id"] = tenant_id or existing.get("tenant_id", "")
        existing["updated_at"] = time.time()
        self.store.save_preference(existing)
        return self._preference_response(existing)

    def get_preference(self, user_id: str) -> PreferenceResponse | None:
        rec = self.store.get_preference(user_id)
        return self._preference_response(rec) if rec else None

    def _preference_response(self, rec: dict[str, Any]) -> PreferenceResponse:
        return PreferenceResponse(
            user_id=rec["user_id"],
            tenant_id=rec.get("tenant_id", ""),
            channel_enabled=rec.get("channel_enabled", {}),
            event_level_min=rec.get("event_level_min", {}),
            quiet_hours_start=rec.get("quiet_hours_start", -1),
            quiet_hours_end=rec.get("quiet_hours_end", -1),
            updated_at=rec.get("updated_at", 0.0),
        )

    # ── Notification list / read ────────────────────────────────

    def list_notifications(
        self,
        *,
        tenant_id: str = "",
        user_id: str = "",
        status: str = "",
        channel_id: str = "",
        event_type: str = "",
        unread_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[NotificationResponse], int]:
        rows, total = self.store.list_notifications(
            tenant_id=tenant_id,
            user_id=user_id,
            status=status,
            channel_id=channel_id,
            event_type=event_type,
            unread_only=unread_only,
            limit=limit,
            offset=offset,
        )
        return [self._notif_response(r) for r in rows], total

    def get_notification(self, notification_id: str) -> NotificationResponse | None:
        rec = self.store.get_notification(notification_id)
        return self._notif_response(rec) if rec else None

    def mark_read(self, notification_id: str) -> bool:
        return self.store.mark_read(notification_id)

    def mark_all_read(self, user_id: str, tenant_id: str = "") -> int:
        return self.store.mark_all_read(user_id, tenant_id)

    def unread_count(self, user_id: str, tenant_id: str = "") -> int:
        return self.store.unread_count(user_id, tenant_id)

    def delete_notification(self, notification_id: str) -> bool:
        return self.store.delete_notification(notification_id)

    def list_dead_letters(self, tenant_id: str = "", limit: int = 100) -> list[NotificationResponse]:
        return [
            self._notif_response(r)
            for r in self.store.list_dead_letters(tenant_id=tenant_id, limit=limit)
        ]

    def _notif_response(self, rec: dict[str, Any]) -> NotificationResponse:
        return NotificationResponse(
            notification_id=rec["notification_id"],
            tenant_id=rec.get("tenant_id", ""),
            user_id=rec.get("user_id", ""),
            channel_id=rec.get("channel_id", ""),
            channel_type=ChannelType(rec.get("channel_type", "inapp")),
            level=NotificationLevel(rec.get("level", "info")),
            title=rec.get("title", ""),
            body=rec.get("body", ""),
            status=NotificationStatus(rec.get("status", "pending")),
            event_type=rec.get("event_type", ""),
            event_payload=rec.get("event_payload", {}),
            retry_count=rec.get("retry_count", 0),
            max_retries=rec.get("max_retries", 3),
            error=rec.get("error", ""),
            created_at=rec.get("created_at", 0.0),
            sent_at=rec.get("sent_at", 0.0),
            read_at=rec.get("read_at", 0.0),
        )

    # ── Event handling (rule matching) ──────────────────────────

    async def _on_event(self, event: Any) -> None:
        """EventBus subscriber — matches rules and dispatches notifications.

        Called for every published event (wildcard subscription). Iterates
        over rules with matching ``event_type`` and ``tenant_id``, applies
        the rule ``filter`` (subset match against event payload), and for
        each matching rule × channel creates a notification + dispatches it.
        """
        rules = self.store.list_rules(tenant_id=event.tenant_id, event_type=event.event_type)
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if not self._filter_matches(rule.get("filter", {}), event.payload):
                continue
            # Update rule trigger stats
            rule["trigger_count"] = int(rule.get("trigger_count", 0)) + 1
            rule["last_triggered_at"] = time.time()
            self.store.save_rule(rule)

            level = NotificationLevel(rule.get("level", "info"))
            template = self.store.get_template(rule.get("template_id", "")) if rule.get("template_id") else None
            title, body = self._render(template, event)

            for channel_id in rule.get("channel_ids", []):
                channel_rec = self.store.get_channel(channel_id)
                if channel_rec is None or not channel_rec.get("enabled", True):
                    continue
                # Tenant isolation: channel must belong to same tenant (or global)
                if (
                    event.tenant_id
                    and channel_rec.get("tenant_id", "")
                    and channel_rec.get("tenant_id", "") != event.tenant_id
                ):
                    continue
                await self._create_and_dispatch(
                    channel_id=channel_id,
                    channel_type=channel_rec["type"],
                    tenant_id=event.tenant_id,
                    user_id=channel_rec.get("config", {}).get("user_id", ""),
                    title=title,
                    body=body,
                    level=level,
                    event_type=event.event_type,
                    event_payload=event.payload,
                )

    @staticmethod
    def _filter_matches(filter_spec: dict[str, Any], payload: dict[str, Any]) -> bool:
        """Subset match: every key in filter_spec must be present and equal in payload."""
        if not filter_spec:
            return True
        for k, v in filter_spec.items():
            if k not in payload:
                return False
            if payload[k] != v:
                return False
        return True

    @staticmethod
    def _render(template: dict[str, Any] | None, event: Any) -> tuple[str, str]:
        """Render title/body from template using ``{placeholder}`` substitution.

        Falls back to ``"{event_type}"`` / JSON dump of payload if no template.
        Uses ``str.format_map`` with a SafeDict so missing keys don't raise.
        """
        if template is None:
            return (
                event.event_type,
                __import__("json").dumps(event.payload, default=str),
            )

        class _SafeDict(dict):
            def __missing__(self, key: str) -> str:
                return "{" + key + "}"

        ctx = _SafeDict(event.payload)
        ctx["event_type"] = event.event_type
        ctx["tenant_id"] = event.tenant_id
        ctx["timestamp"] = event.timestamp
        try:
            subject = template.get("subject", "").format_map(ctx)
            body = template.get("body", "").format_map(ctx)
        except Exception:
            subject = template.get("subject", "")
            body = template.get("body", "")
        return subject or event.event_type, body

    # ── Direct send (bypass rules) ──────────────────────────────

    async def send_notification(
        self,
        *,
        channel_id: str,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        tenant_id: str = "",
        user_id: str = "",
        event_type: str = "",
        event_payload: dict[str, Any] | None = None,
    ) -> NotificationResponse:
        """Send a notification directly to a channel (no rule matching)."""
        channel_rec = self.store.get_channel(channel_id)
        if channel_rec is None:
            raise ValueError(f"Channel not found: {channel_id}")
        return await self._create_and_dispatch(
            channel_id=channel_id,
            channel_type=channel_rec["type"],
            tenant_id=tenant_id,
            user_id=user_id,
            title=title,
            body=body,
            level=level,
            event_type=event_type,
            event_payload=event_payload or {},
        )

    async def _create_and_dispatch(
        self,
        *,
        channel_id: str,
        channel_type: str,
        tenant_id: str,
        user_id: str,
        title: str,
        body: str,
        level: NotificationLevel,
        event_type: str,
        event_payload: dict[str, Any],
    ) -> NotificationResponse:
        notif_id = self.store.new_id("notif")
        now = time.time()
        rec = {
            "notification_id": notif_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "channel_id": channel_id,
            "channel_type": channel_type,
            "level": level.value,
            "title": title,
            "body": body,
            "status": NotificationStatus.PENDING.value,
            "event_type": event_type,
            "event_payload": event_payload,
            "retry_count": 0,
            "max_retries": self.max_retries,
            "error": "",
            "created_at": now,
            "sent_at": 0.0,
            "read_at": 0.0,
        }
        self.store.save_notification(rec)
        response = self._notif_response(rec)

        # For InApp, broadcast immediately (the "delivery" is the broadcast).
        if channel_type == ChannelType.INAPP.value:
            await self._broadcast({"type": "notification", "data": rec})

        # Dispatch delivery in the background (don't block the caller).
        # 必须保存 create_task 的返回值：asyncio 只对 pending task 持弱引用，
        # 若此处不保存，task 可能在事件循环调度前被 GC，投递永远不会执行。
        task = asyncio.create_task(self._deliver(notif_id, channel_id))
        self._delivery_tasks.add(task)
        task.add_done_callback(self._delivery_tasks.discard)
        return response

    async def _deliver(self, notif_id: str, channel_id: str) -> None:
        """Attempt delivery with retry. Updates the notification record."""
        rec = self.store.get_notification(notif_id)
        if rec is None:
            return
        channel = self._instantiate_channel(channel_id)
        if channel is None:
            rec["status"] = NotificationStatus.FAILED.value
            rec["error"] = "Channel not available or disabled"
            self.store.save_notification(rec)
            return

        # InApp channels don't need external delivery — mark as sent.
        if rec["channel_type"] == ChannelType.INAPP.value:
            rec["status"] = NotificationStatus.SENT.value
            rec["sent_at"] = time.time()
            self.store.save_notification(rec)
            return

        attempt = 0
        while attempt <= self.max_retries:
            try:
                result = await asyncio.to_thread(
                    channel.send,
                    title=rec["title"],
                    body=rec["body"],
                    level=NotificationLevel(rec["level"]),
                )
            except Exception as exc:
                result = {"success": False, "error": str(exc)}

            if result.get("success"):
                rec["status"] = NotificationStatus.SENT.value
                rec["sent_at"] = time.time()
                rec["error"] = ""
                self.store.save_notification(rec)
                # Update channel status to active (clear any prior error)
                ch_rec = self.store.get_channel(channel_id)
                if ch_rec:
                    ch_rec["status"] = ChannelStatus.ACTIVE.value
                    ch_rec["last_error"] = ""
                    ch_rec["updated_at"] = time.time()
                    self.store.save_channel(ch_rec)
                return

            # Failure — retry with backoff
            attempt += 1
            rec["retry_count"] = attempt
            rec["error"] = str(result.get("error", "unknown"))
            if attempt <= self.max_retries:
                rec["status"] = NotificationStatus.RETRYING.value
                self.store.save_notification(rec)
                backoff = self.retry_backoff_s * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)
            else:
                rec["status"] = NotificationStatus.DEAD_LETTER.value
                self.store.save_notification(rec)
                # Mark channel as error
                ch_rec = self.store.get_channel(channel_id)
                if ch_rec:
                    ch_rec["status"] = ChannelStatus.ERROR.value
                    ch_rec["last_error"] = rec["error"]
                    ch_rec["updated_at"] = time.time()
                    self.store.save_channel(ch_rec)
                logger.warning(
                    "[notification.manager] dead-letter %s after %d retries: %s",
                    notif_id, attempt, rec["error"],
                )

    # ── Diagnostics ─────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return aggregate stats for the dashboard."""
        bus_stats = self.event_bus.stats()
        # Count notifications by status (cheap queries).
        # P1 #22 fix: list_notifications 返回 (rows, total) —— 旧代码
        # `sent, _ = ...` 把 rows 列表当成了计数（类型错误，API 契约破坏）。
        _, sent = self.store.list_notifications(status="sent", limit=1)
        _, pending = self.store.list_notifications(status="pending", limit=1)
        _, retrying = self.store.list_notifications(status="retrying", limit=1)
        _, dead = self.store.list_notifications(status="dead_letter", limit=1)
        return {
            "event_bus": bus_stats,
            "channels": len(self.store.list_channels()),
            "rules": len(self.store.list_rules()),
            "templates": len(self.store.list_templates()),
            "statuses": {
                "sent": sent,
                "pending": pending,
                "retrying": retrying,
                "dead_letter": dead,
            },
        }