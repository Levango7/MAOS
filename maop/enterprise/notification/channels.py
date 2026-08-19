"""Channel abstraction and built-in implementations.

A *channel* is a delivery transport for a notification. The base class
``BaseChannel`` defines the contract; three implementations are bundled:

  - ``EmailChannel``    SMTP (smtplib.SMTP/SMTP_SSL) with TLS + auth
  - ``WebhookChannel`` HTTP POST (httpx, sync fallback to urllib)
  - ``InAppChannel``    In-process storage (read via NotificationManager)

Custom channels are registered via ``register_channel`` and instantiated
by ``get_channel_class``. Each channel receives a ``config`` dict (already
decrypted — secret fields like ``password`` / ``secret`` are unmasked by
the store before being passed in).

All ``send`` methods are *sync* by design — the manager wraps them in
``asyncio.to_thread`` so the event loop is never blocked.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from maop.enterprise.notification.models import ChannelType, NotificationLevel

logger = logging.getLogger(__name__)


# ── Registry ──────────────────────────────────────────────────────

_CHANNEL_REGISTRY: dict[str, type[BaseChannel]] = {}


def register_channel(type_name: str, cls: type[BaseChannel]) -> None:
    """Register a custom channel implementation.

    Args:
        type_name: lowercase string key (e.g. ``"slack"``)
        cls:       subclass of :class:`BaseChannel`
    """
    if not issubclass(cls, BaseChannel):
        raise TypeError(f"{cls!r} must subclass BaseChannel")
    _CHANNEL_REGISTRY[type_name.lower()] = cls
    logger.debug("[channel] registered type %s -> %s", type_name, cls.__name__)


def get_channel_class(type_name: str) -> type[BaseChannel]:
    """Look up a registered channel class by type name.

    Raises:
        KeyError: if ``type_name`` is not registered.
    """
    key = type_name.lower()
    if key not in _CHANNEL_REGISTRY:
        raise KeyError(f"Unknown channel type: {type_name!r}")
    return _CHANNEL_REGISTRY[key]


# ── Base channel ──────────────────────────────────────────────────


class BaseChannel(ABC):
    """Abstract base class for all notification channels.

    Subclasses implement :meth:`send` and optionally :meth:`validate_config`.
    The constructor receives the decrypted ``config`` dict and the channel
    metadata (``channel_id``, ``name``, ``tenant_id``).

    The ``send`` method must return a dict with at least ``success: bool``.
    On failure, include ``error: str`` so the manager can record it.
    """

    type_name: str = "base"

    def __init__(
        self,
        *,
        channel_id: str = "",
        name: str = "",
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> None:
        self.channel_id = channel_id
        self.name = name
        self.tenant_id = tenant_id
        self.config: dict[str, Any] = config or {}

    @abstractmethod
    def send(
        self,
        *,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        recipient: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deliver a notification.

        Args:
            title:    notification title / subject
            body:     notification body (plain text)
            level:    severity level
            recipient: optional recipient override (e.g. email address)
            context:  optional event context dict for templating

        Returns:
            dict with ``success: bool`` and optional ``error: str``,
            ``message_id: str``, ``metadata: dict``.
        """
        raise NotImplementedError

    def validate_config(self) -> dict[str, Any]:
        """Check that ``self.config`` has the required fields.

        Returns:
            dict with ``valid: bool`` and optional ``errors: list[str]``.
        Default implementation returns ``{"valid": True}``.
        """
        return {"valid": True}

    def mask_config(self) -> dict[str, Any]:
        """Return a copy of ``self.config`` with secret fields masked.

        Default masks ``password``, ``secret``, ``api_key``, ``token``.
        Subclasses can override for custom secret field names.
        """
        secret_keys = {"password", "secret", "api_key", "token", "auth_token"}
        masked: dict[str, Any] = {}
        for k, v in self.config.items():
            masked[k] = "***" if k.lower() in secret_keys and v else v
        return masked


# ── Email channel ─────────────────────────────────────────────────


class EmailChannel(BaseChannel):
    """SMTP email delivery.

    Config fields:
      - ``host`` (str, required): SMTP server host
      - ``port`` (int, default 587): SMTP server port
      - ``username`` (str): SMTP auth username
      - ``password`` (str): SMTP auth password (decrypted by store)
      - ``use_tls`` (bool, default True): STARTTLS
      - ``use_ssl`` (bool, default False): SMTP_SSL (implicit TLS)
      - ``from_addr`` (str, required): From header
      - ``to_addrs`` (list[str]): default recipients (overridable per send)
      - ``timeout_s`` (int, default 30): socket timeout
    """

    type_name = "email"

    def validate_config(self) -> dict[str, Any]:
        errors: list[str] = []
        if not self.config.get("host"):
            errors.append("host is required")
        if not self.config.get("from_addr"):
            errors.append("from_addr is required")
        return {"valid": not errors, "errors": errors}

    def send(
        self,
        *,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        recipient: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        cfg = self.config
        host = cfg.get("host", "")
        port = int(cfg.get("port", 587))
        username = cfg.get("username", "")
        password = cfg.get("password", "")
        use_tls = bool(cfg.get("use_tls", True))
        use_ssl = bool(cfg.get("use_ssl", False))
        from_addr = cfg.get("from_addr", "")
        timeout_s = int(cfg.get("timeout_s", 30))

        # Resolve recipients: explicit recipient > to_addrs in config
        if recipient:
            to_list = [r.strip() for r in recipient.split(",") if r.strip()]
        else:
            to_list = list(cfg.get("to_addrs", []))
        if not to_list:
            return {"success": False, "error": "No recipients configured"}
        if not host or not from_addr:
            return {"success": False, "error": "host and from_addr are required"}

        # Build MIME message
        msg = MIMEMultipart("alternative")
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_list)
        msg["Subject"] = title or "(no subject)"
        msg.attach(MIMEText(body, "plain", "utf-8"))

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, timeout=timeout_s, context=ctx) as smtp:
                    if username:
                        smtp.login(username, password)
                    smtp.sendmail(from_addr, to_list, msg.as_string())
            else:
                with smtplib.SMTP(host, port, timeout=timeout_s) as smtp:
                    smtp.ehlo()
                    if use_tls:
                        smtp.starttls(context=ssl.create_default_context())
                        smtp.ehlo()
                    if username:
                        smtp.login(username, password)
                    smtp.sendmail(from_addr, to_list, msg.as_string())
            return {"success": True, "message_id": msg["Message-ID"] or ""}
        except Exception as exc:
            logger.warning("[channel:email] send failed: %s", exc)
            return {"success": False, "error": str(exc)}


# ── Webhook channel ───────────────────────────────────────────────


class WebhookChannel(BaseChannel):
    """HTTP POST webhook delivery.

    Config fields:
      - ``url`` (str, required): webhook endpoint URL
      - ``method`` (str, default POST): HTTP method
      - ``secret`` (str): HMAC-SHA256 signing secret (sent as
        ``X-MAOP-Signature`` header, hex digest of HMAC over the JSON body)
      - ``headers`` (dict[str, str]): extra static headers
      - ``timeout_s`` (int, default 30): request timeout
      - ``ssl_verify`` (bool, default True): verify TLS certs
    """

    type_name = "webhook"

    def validate_config(self) -> dict[str, Any]:
        errors: list[str] = []
        if not self.config.get("url"):
            errors.append("url is required")
        return {"valid": not errors, "errors": errors}

    def _sign(self, body: bytes, secret: str) -> str:
        import hashlib
        import hmac
        return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def send(
        self,
        *,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        recipient: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        cfg = self.config
        url = cfg.get("url", "")
        if not url:
            return {"success": False, "error": "url is required"}
        method = cfg.get("method", "POST").upper()
        timeout_s = int(cfg.get("timeout_s", 30))
        secret = cfg.get("secret", "")
        extra_headers = dict(cfg.get("headers", {}))

        payload = {
            "title": title,
            "body": body,
            "level": level.value,
            "channel_id": self.channel_id,
            "tenant_id": self.tenant_id,
            "timestamp": time.time(),
            "context": context or {},
        }
        body_bytes = json.dumps(payload).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        headers.update(extra_headers)
        if secret:
            headers["X-MAOP-Signature"] = self._sign(body_bytes, secret)

        try:
            req = urllib.request.Request(
                url, data=body_bytes, headers=headers, method=method
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                status = resp.status
                resp_body = resp.read().decode("utf-8", errors="replace")
            if 200 <= status < 300:
                return {"success": True, "status_code": status, "response": resp_body[:500]}
            return {"success": False, "error": f"HTTP {status}: {resp_body[:200]}", "status_code": status}
        except urllib.error.HTTPError as exc:
            return {"success": False, "error": f"HTTP {exc.code}: {exc.reason}", "status_code": exc.code}
        except Exception as exc:
            logger.warning("[channel:webhook] send failed: %s", exc)
            return {"success": False, "error": str(exc)}


# ── In-app channel ────────────────────────────────────────────────


class InAppChannel(BaseChannel):
    """In-app notification — stored in the notifications table.

    This channel does NOT actually "send" anywhere external; it just marks
    the notification as ``sent`` and stores it for later retrieval via
    ``NotificationManager.list_notifications``. The manager handles the
    DB write before calling ``send``, so here we just return success.

    Config fields:
      - ``user_id`` (str): default user to address (overridable per send)
    """

    type_name = "inapp"

    def send(
        self,
        *,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        recipient: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # The actual persistence is done by NotificationManager before
        # invoking the channel. InApp just confirms delivery.
        return {
            "success": True,
            "message_id": "",
            "metadata": {"recipient": recipient or self.config.get("user_id", "")},
        }


# ── Auto-register built-in channels ───────────────────────────────

register_channel(ChannelType.EMAIL.value, EmailChannel)
register_channel(ChannelType.WEBHOOK.value, WebhookChannel)
register_channel(ChannelType.INAPP.value, InAppChannel)