"""Event bus — lightweight in-process pub/sub for system events.

The bus is intentionally simple (no external broker dependency). It
supports:
  - Multiple subscribers per event type
  - Wildcard subscribers (``"*"`` receives all events)
  - Async handlers (``async def``) and sync handlers (wrapped via
    ``asyncio.to_thread``)
  - Error isolation — one failing handler does not block others
  - Optional history buffer (ring buffer) for debugging / replay

For multi-process / distributed deployments, swap :class:`EventBus` for
a Redis/RabbitMQ-backed implementation — the public API (``subscribe`` /
``publish``) stays the same.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any

from maop.enterprise.notification.models import EventPayload, EventType

logger = logging.getLogger(__name__)

# Type alias for event handlers. Sync handlers return Any; async handlers
# return Awaitable[Any]. The bus detects which by inspecting the callable
# (``asyncio.iscoroutinefunction``) so sync handlers are offloaded to
# ``asyncio.to_thread`` instead of blocking the event loop.
EventHandler = Callable[[EventPayload], Any | Awaitable[Any]]


class EventBus:
    """In-process async event bus.

    Usage::

        bus = EventBus()
        bus.subscribe("task_failed", my_async_handler)
        await bus.publish(EventPayload(event_type="task_failed", payload={...}))

    The bus is safe to use from multiple coroutines within the same event
    loop. For cross-loop / cross-process delivery, use a Redis-backed bus.
    """

    def __init__(
        self,
        *,
        history_size: int = 1000,
        log_unmatched: bool = False,
    ) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: deque[EventPayload] = deque(maxlen=history_size)
        self._history_size = history_size
        self._log_unmatched = log_unmatched
        # Stats counters
        self._publish_count: int = 0
        self._deliver_count: int = 0
        self._error_count: int = 0

    # ── Subscription ──────────────────────────────────────────────

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register ``handler`` for ``event_type``.

        Use ``"*"`` as a wildcard to receive all events. Multiple handlers
        per event type are supported; they are invoked in registration order.
        """
        if not callable(handler):
            raise TypeError(f"handler must be callable, got {type(handler)!r}")
        self._subscribers[event_type].append(handler)
        logger.debug("[event_bus] subscribed %s -> %s", event_type, getattr(handler, "__name__", repr(handler)))

    def unsubscribe(self, event_type: str, handler: EventHandler) -> bool:
        """Remove a previously-registered handler. Returns True if removed."""
        handlers = self._subscribers.get(event_type, [])
        try:
            handlers.remove(handler)
            return True
        except ValueError:
            return False

    def subscribers(self, event_type: str = "") -> dict[str, int]:
        """Return subscriber counts per event type (for diagnostics)."""
        if event_type:
            return {event_type: len(self._subscribers.get(event_type, []))}
        return {et: len(hs) for et, hs in self._subscribers.items() if hs}

    # ── Publishing ────────────────────────────────────────────────

    async def publish(self, event: EventPayload) -> int:
        """Publish ``event`` to all matching subscribers.

        Sets ``event.timestamp`` if zero. Records the event in the history
        buffer. Returns the number of handlers invoked.
        """
        if not event.timestamp:
            event.timestamp = time.time()
        self._publish_count += 1
        self._history.append(event)

        handlers: list[EventHandler] = []
        handlers.extend(self._subscribers.get(event.event_type, []))
        handlers.extend(self._subscribers.get("*", []))

        if not handlers:
            if self._log_unmatched:
                logger.debug("[event_bus] no subscribers for %s", event.event_type)
            return 0

        # Invoke all handlers concurrently. Errors in one handler do not
        # affect others — gather(return_exceptions=True) ensures isolation.
        tasks = [self._invoke(handler, event) for handler in handlers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                self._error_count += 1
                logger.warning("[event_bus] handler error: %s", r, exc_info=r)
            else:
                self._deliver_count += 1
        return len(handlers)

    async def _invoke(self, handler: EventHandler, event: EventPayload) -> Any:
        """Invoke a handler. Async handlers are awaited directly; plain sync
        handlers are wrapped in ``asyncio.to_thread`` so they never block the
        event loop (per module docstring)."""
        if asyncio.iscoroutinefunction(handler):
            return await handler(event)
        # Sync handler → run in a worker thread. We detect async-ness upfront
        # (instead of calling the handler first and inspecting its return
        # value) so a sync handler is never invoked twice.
        return await asyncio.to_thread(handler, event)

    # ── Convenience: publish from raw fields ─────────────────────

    async def emit(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        tenant_id: str = "",
    ) -> int:
        """Shorthand for ``publish(EventPayload(...))``.

        Validates ``event_type`` against :class:`EventType` (logs a warning
        for unknown types but still publishes — forward compatible).
        """
        try:
            EventType(event_type)
        except ValueError:
            logger.debug("[event_bus] non-canonical event_type: %s", event_type)
        return await self.publish(
            EventPayload(
                event_type=event_type,
                payload=payload or {},
                tenant_id=tenant_id,
            )
        )

    # ── History & stats ──────────────────────────────────────────

    def history(self, event_type: str = "", limit: int = 100) -> list[EventPayload]:
        """Return recent events from the history buffer (newest last)."""
        events = list(self._history)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    def stats(self) -> dict[str, Any]:
        """Return bus statistics for diagnostics."""
        return {
            "publish_count": self._publish_count,
            "deliver_count": self._deliver_count,
            "error_count": self._error_count,
            "subscriber_count": sum(len(hs) for hs in self._subscribers.values()),
            "history_size": len(self._history),
        }

    def clear(self) -> None:
        """Reset all subscribers, history and stats (mainly for tests)."""
        self._subscribers.clear()
        self._history.clear()
        self._publish_count = 0
        self._deliver_count = 0
        self._error_count = 0