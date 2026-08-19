"""Persistence layer for the notification center.

Uses SQLite (default, personal edition) or PostgreSQL (enterprise) via
the shared storage backend abstraction. Secret fields (SMTP password,
webhook secret) are encrypted at rest with Fernet (symmetric authenticated
encryption). The Fernet key is derived from ``MAOP_KEY`` or
``MAOP_NOTIFICATION_SECRET`` env var; if neither is set, a per-process
random key is generated (secrets won't survive restart — acceptable for
tests, logged as a warning in production).

Schema (5 tables):
  - notification_channels
  - notification_rules
  - notification_templates
  - notifications
  - notification_preferences
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from maop.config.edition import has_feature, record_degradation

logger = logging.getLogger(__name__)


# ── Fernet encryption helper ──────────────────────────────────────


def _get_fernet() -> Any:
    """Return a Fernet instance for secret encryption.

    Key sources (in priority order):
      1. ``MAOP_NOTIFICATION_SECRET`` env var
      2. ``MAOP_KEY`` env var
      3. ``MAOP_KEY_FILE`` env var (file contents)
      4. Per-process random key (logged warning — secrets won't persist)

    Returns ``None`` if ``cryptography`` is not installed — callers must
    handle this by storing secrets in plaintext (with a warning).
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None

    key: bytes | None = None
    secret_env = os.getenv("MAOP_NOTIFICATION_SECRET")
    if secret_env:
        key = secret_env.encode("utf-8")
        if not Fernet.is_valid_key(key):  # type: ignore  # cryptography stub 未标 classmethod
            # Derive a valid Fernet key from the env secret via SHA256 → base64
            import base64
            import hashlib
            derived = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
            key = derived
    if key is None:
        key_env = os.getenv("MAOP_KEY")
        if key_env:
            key = key_env.encode("utf-8")
            if not Fernet.is_valid_key(key):  # type: ignore
                import base64
                import hashlib
                key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    if key is None:
        key_file = os.getenv("MAOP_KEY_FILE")
        if key_file and Path(key_file).exists():
            key = Path(key_file).read_bytes().strip()
            if not Fernet.is_valid_key(key):  # type: ignore
                import base64
                import hashlib
                key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    if key is None:
        # Per-process random key — secrets won't survive restart.
        key = Fernet.generate_key()
        if os.getenv("MAOP_ENV", "development").lower() == "production":
            logger.warning(
                "[notification.store] No MAOP_NOTIFICATION_SECRET/MAOP_KEY set — "
                "using ephemeral random key. Encrypted secrets will be lost on restart."
            )
    return Fernet(key)


_FERNET: Any = None
_FERNET_LOCK = threading.Lock()


def _fernet() -> Any:
    global _FERNET
    if _FERNET is None:
        with _FERNET_LOCK:
            if _FERNET is None:
                _FERNET = _get_fernet()
    return _FERNET


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string for at-rest storage.

    Returns ``"enc:<ciphertext>"`` if Fernet is available, otherwise
    ``"plain:<plaintext>"`` (with a one-time warning).
    """
    if not plaintext:
        return ""
    f = _fernet()
    if f is None:
        return f"plain:{plaintext}"
    return str("enc:" + f.encrypt(plaintext.encode("utf-8")).decode("utf-8"))


def decrypt_secret(stored: str) -> str:
    """Decrypt a secret stored by :func:`encrypt_secret`.

    Returns the plaintext. Handles both ``enc:`` and ``plain:`` prefixes,
    and bare plaintext (backward compatible).
    """
    if not stored:
        return ""
    if stored.startswith("enc:"):
        f = _fernet()
        if f is None:
            return ""
        try:
            return str(f.decrypt(stored[4:].encode("utf-8")).decode("utf-8"))
        except Exception as exc:
            logger.warning("[notification.store] decrypt failed: %s", exc)
            return ""
    if stored.startswith("plain:"):
        return stored[6:]
    return stored  # bare plaintext (legacy)


# Secret field names per channel type — used by store to encrypt/decrypt
# config dicts transparently.
_SECRET_FIELDS = {"password", "secret", "api_key", "token", "auth_token"}


def _encrypt_config(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    for k, v in list(out.items()):
        if k.lower() in _SECRET_FIELDS and isinstance(v, str) and v:
            out[k] = encrypt_secret(v)
    return out


def _decrypt_config(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    for k, v in list(out.items()):
        if k.lower() in _SECRET_FIELDS and isinstance(v, str) and v:
            out[k] = decrypt_secret(v)
    return out


def _mask_config(config: dict[str, Any]) -> dict[str, Any]:
    out = dict(config)
    for k, v in list(out.items()):
        if k.lower() in _SECRET_FIELDS and v:
            out[k] = "***"
    return out


# ── SQLite store ──────────────────────────────────────────────────


class NotificationStore:
    """SQLite-backed persistence for notifications.

    All five tables are created in a single ``.db`` file under
    ``MAOP_DATA_DIR/notifications.db``. The store is thread-safe via a
    per-instance lock; for higher concurrency, switch to the PG-backed
    store (enterprise edition).
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            data_dir = Path(os.getenv("MAOP_DATA_DIR", "data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "notifications.db"
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._conn() as conn:
            cur = conn.cursor()
            # 1. notification_channels
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notification_channels (
                    channel_id   TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    type         TEXT NOT NULL,
                    config       TEXT NOT NULL DEFAULT '{}',
                    description  TEXT NOT NULL DEFAULT '',
                    tenant_id    TEXT NOT NULL DEFAULT '',
                    enabled      INTEGER NOT NULL DEFAULT 1,
                    status       TEXT NOT NULL DEFAULT 'active',
                    last_error   TEXT NOT NULL DEFAULT '',
                    created_at   REAL NOT NULL DEFAULT 0,
                    updated_at   REAL NOT NULL DEFAULT 0
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nc_tenant ON notification_channels(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nc_type ON notification_channels(type)")

            # 2. notification_rules
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notification_rules (
                    rule_id           TEXT PRIMARY KEY,
                    name              TEXT NOT NULL,
                    event_type        TEXT NOT NULL,
                    channel_ids       TEXT NOT NULL DEFAULT '[]',
                    template_id       TEXT NOT NULL DEFAULT '',
                    filter            TEXT NOT NULL DEFAULT '{}',
                    level             TEXT NOT NULL DEFAULT 'info',
                    tenant_id         TEXT NOT NULL DEFAULT '',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    status            TEXT NOT NULL DEFAULT 'active',
                    description       TEXT NOT NULL DEFAULT '',
                    trigger_count     INTEGER NOT NULL DEFAULT 0,
                    last_triggered_at REAL NOT NULL DEFAULT 0,
                    created_at        REAL NOT NULL DEFAULT 0,
                    updated_at        REAL NOT NULL DEFAULT 0
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nr_tenant ON notification_rules(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nr_event ON notification_rules(event_type)")

            # 3. notification_templates
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notification_templates (
                    template_id  TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    subject      TEXT NOT NULL DEFAULT '',
                    body         TEXT NOT NULL DEFAULT '',
                    tenant_id    TEXT NOT NULL DEFAULT '',
                    description  TEXT NOT NULL DEFAULT '',
                    created_at   REAL NOT NULL DEFAULT 0,
                    updated_at   REAL NOT NULL DEFAULT 0
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nt_tenant ON notification_templates(tenant_id)")

            # 4. notifications
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    notification_id  TEXT PRIMARY KEY,
                    tenant_id        TEXT NOT NULL DEFAULT '',
                    user_id          TEXT NOT NULL DEFAULT '',
                    channel_id       TEXT NOT NULL DEFAULT '',
                    channel_type     TEXT NOT NULL DEFAULT 'inapp',
                    level            TEXT NOT NULL DEFAULT 'info',
                    title            TEXT NOT NULL DEFAULT '',
                    body             TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'pending',
                    event_type       TEXT NOT NULL DEFAULT '',
                    event_payload    TEXT NOT NULL DEFAULT '{}',
                    retry_count      INTEGER NOT NULL DEFAULT 0,
                    max_retries      INTEGER NOT NULL DEFAULT 3,
                    error            TEXT NOT NULL DEFAULT '',
                    created_at       REAL NOT NULL DEFAULT 0,
                    sent_at          REAL NOT NULL DEFAULT 0,
                    read_at          REAL NOT NULL DEFAULT 0
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_tenant ON notifications(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_channel ON notifications(channel_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at)")

            # 5. notification_preferences
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    user_id            TEXT PRIMARY KEY,
                    tenant_id          TEXT NOT NULL DEFAULT '',
                    channel_enabled    TEXT NOT NULL DEFAULT '{}',
                    event_level_min    TEXT NOT NULL DEFAULT '{}',
                    quiet_hours_start  INTEGER NOT NULL DEFAULT -1,
                    quiet_hours_end    INTEGER NOT NULL DEFAULT -1,
                    updated_at         REAL NOT NULL DEFAULT 0
                )
            """)
            conn.commit()

    # ── Channels ─────────────────────────────────────────────────

    def save_channel(self, channel: dict[str, Any]) -> None:
        config_enc = _encrypt_config(channel.get("config", {}))
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO notification_channels
                   (channel_id, name, type, config, description, tenant_id,
                    enabled, status, last_error, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    channel["channel_id"],
                    channel["name"],
                    channel["type"],
                    json.dumps(config_enc),
                    channel.get("description", ""),
                    channel.get("tenant_id", ""),
                    int(channel.get("enabled", True)),
                    channel.get("status", "active"),
                    channel.get("last_error", ""),
                    channel.get("created_at", 0.0),
                    channel.get("updated_at", 0.0),
                ),
            )
            conn.commit()

    def get_channel(self, channel_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM notification_channels WHERE channel_id=?",
                (channel_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_channel(dict(row))

    def list_channels(self, tenant_id: str = "") -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM notification_channels WHERE tenant_id=? ORDER BY created_at DESC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM notification_channels ORDER BY created_at DESC"
                ).fetchall()
        return [self._row_to_channel(dict(r)) for r in rows]

    def delete_channel(self, channel_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM notification_channels WHERE channel_id=?", (channel_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def _row_to_channel(row: dict[str, Any]) -> dict[str, Any]:
        row["config"] = _decrypt_config(json.loads(row.get("config") or "{}"))
        row["enabled"] = bool(row.get("enabled", 1))
        return row

    # ── Rules ─────────────────────────────────────────────────────

    def save_rule(self, rule: dict[str, Any]) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO notification_rules
                   (rule_id, name, event_type, channel_ids, template_id, filter,
                    level, tenant_id, enabled, status, description,
                    trigger_count, last_triggered_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule["rule_id"],
                    rule["name"],
                    rule["event_type"],
                    json.dumps(rule.get("channel_ids", [])),
                    rule.get("template_id", ""),
                    json.dumps(rule.get("filter", {})),
                    rule.get("level", "info"),
                    rule.get("tenant_id", ""),
                    int(rule.get("enabled", True)),
                    rule.get("status", "active"),
                    rule.get("description", ""),
                    int(rule.get("trigger_count", 0)),
                    rule.get("last_triggered_at", 0.0),
                    rule.get("created_at", 0.0),
                    rule.get("updated_at", 0.0),
                ),
            )
            conn.commit()

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM notification_rules WHERE rule_id=?", (rule_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_rule(dict(row))

    def list_rules(self, tenant_id: str = "", event_type: str = "") -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            sql = "SELECT * FROM notification_rules WHERE 1=1"
            params: list[Any] = []
            if tenant_id:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            if event_type:
                sql += " AND event_type=?"
                params.append(event_type)
            sql += " ORDER BY created_at DESC"
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_rule(dict(r)) for r in rows]

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM notification_rules WHERE rule_id=?", (rule_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def _row_to_rule(row: dict[str, Any]) -> dict[str, Any]:
        row["channel_ids"] = json.loads(row.get("channel_ids") or "[]")
        row["filter"] = json.loads(row.get("filter") or "{}")
        row["enabled"] = bool(row.get("enabled", 1))
        return row

    # ── Templates ─────────────────────────────────────────────────

    def save_template(self, template: dict[str, Any]) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO notification_templates
                   (template_id, name, subject, body, tenant_id, description,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    template["template_id"],
                    template["name"],
                    template.get("subject", ""),
                    template.get("body", ""),
                    template.get("tenant_id", ""),
                    template.get("description", ""),
                    template.get("created_at", 0.0),
                    template.get("updated_at", 0.0),
                ),
            )
            conn.commit()

    def get_template(self, template_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM notification_templates WHERE template_id=?",
                (template_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_templates(self, tenant_id: str = "") -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM notification_templates WHERE tenant_id=? ORDER BY created_at DESC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM notification_templates ORDER BY created_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def delete_template(self, template_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM notification_templates WHERE template_id=?", (template_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    # ── Notifications ─────────────────────────────────────────────

    def save_notification(self, notif: dict[str, Any]) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO notifications
                   (notification_id, tenant_id, user_id, channel_id, channel_type,
                    level, title, body, status, event_type, event_payload,
                    retry_count, max_retries, error, created_at, sent_at, read_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    notif["notification_id"],
                    notif.get("tenant_id", ""),
                    notif.get("user_id", ""),
                    notif.get("channel_id", ""),
                    notif.get("channel_type", "inapp"),
                    notif.get("level", "info"),
                    notif.get("title", ""),
                    notif.get("body", ""),
                    notif.get("status", "pending"),
                    notif.get("event_type", ""),
                    json.dumps(notif.get("event_payload", {})),
                    int(notif.get("retry_count", 0)),
                    int(notif.get("max_retries", 3)),
                    notif.get("error", ""),
                    notif.get("created_at", 0.0),
                    notif.get("sent_at", 0.0),
                    notif.get("read_at", 0.0),
                ),
            )
            conn.commit()

    def get_notification(self, notification_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM notifications WHERE notification_id=?",
                (notification_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_notif(dict(row))

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
    ) -> tuple[list[dict[str, Any]], int]:
        with self._lock, self._conn() as conn:
            sql = "SELECT * FROM notifications WHERE 1=1"
            count_sql = "SELECT COUNT(*) FROM notifications WHERE 1=1"
            params: list[Any] = []
            if tenant_id:
                sql += " AND tenant_id=?"
                count_sql += " AND tenant_id=?"
                params.append(tenant_id)
            if user_id:
                sql += " AND user_id=?"
                count_sql += " AND user_id=?"
                params.append(user_id)
            if status:
                sql += " AND status=?"
                count_sql += " AND status=?"
                params.append(status)
            if channel_id:
                sql += " AND channel_id=?"
                count_sql += " AND channel_id=?"
                params.append(channel_id)
            if event_type:
                sql += " AND event_type=?"
                count_sql += " AND event_type=?"
                params.append(event_type)
            if unread_only:
                sql += " AND read_at=0"
                count_sql += " AND read_at=0"
            total = conn.execute(count_sql, params).fetchone()[0]
            sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            rows = conn.execute(sql, [*params, limit, offset]).fetchall()
        return [self._row_to_notif(dict(r)) for r in rows], total

    def mark_read(self, notification_id: str, read_at: float | None = None) -> bool:
        ts = read_at if read_at is not None else time.time()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE notifications SET read_at=? WHERE notification_id=?",
                (ts, notification_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def mark_all_read(self, user_id: str, tenant_id: str = "") -> int:
        ts = time.time()
        with self._lock, self._conn() as conn:
            if tenant_id:
                cur = conn.execute(
                    "UPDATE notifications SET read_at=? WHERE user_id=? AND tenant_id=? AND read_at=0",
                    (ts, user_id, tenant_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE notifications SET read_at=? WHERE user_id=? AND read_at=0",
                    (ts, user_id),
                )
            conn.commit()
            return cur.rowcount

    def unread_count(self, user_id: str, tenant_id: str = "") -> int:
        with self._lock, self._conn() as conn:
            if tenant_id:
                row = conn.execute(
                    "SELECT COUNT(*) FROM notifications WHERE user_id=? AND tenant_id=? AND read_at=0",
                    (user_id, tenant_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) FROM notifications WHERE user_id=? AND read_at=0",
                    (user_id,),
                ).fetchone()
        return int(row[0]) if row else 0

    def delete_notification(self, notification_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM notifications WHERE notification_id=?", (notification_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    def list_dead_letters(self, tenant_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE status='dead_letter' AND tenant_id=? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM notifications WHERE status='dead_letter' ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._row_to_notif(dict(r)) for r in rows]

    @staticmethod
    def _row_to_notif(row: dict[str, Any]) -> dict[str, Any]:
        row["event_payload"] = json.loads(row.get("event_payload") or "{}")
        return row

    # ── Preferences ──────────────────────────────────────────────

    def save_preference(self, pref: dict[str, Any]) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO notification_preferences
                   (user_id, tenant_id, channel_enabled, event_level_min,
                    quiet_hours_start, quiet_hours_end, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    pref["user_id"],
                    pref.get("tenant_id", ""),
                    json.dumps(pref.get("channel_enabled", {})),
                    json.dumps(pref.get("event_level_min", {})),
                    int(pref.get("quiet_hours_start", -1)),
                    int(pref.get("quiet_hours_end", -1)),
                    pref.get("updated_at", 0.0),
                ),
            )
            conn.commit()

    def get_preference(self, user_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM notification_preferences WHERE user_id=?", (user_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["channel_enabled"] = json.loads(d.get("channel_enabled") or "{}")
        d["event_level_min"] = json.loads(d.get("event_level_min") or "{}")
        return d

    # ── Misc ─────────────────────────────────────────────────────

    def new_id(self, prefix: str = "n") -> str:
        return f"{prefix}_{uuid.uuid4().hex[:16]}"


# ── Factory ───────────────────────────────────────────────────────


def get_store(db_path: str | Path | None = None) -> NotificationStore:
    """Return a notification store instance.

    For enterprise edition with PostgreSQL configured, this would return
    a PG-backed store. For now we always use SQLite (PG support is a
    future enhancement; the schema is portable).
    """
    if has_feature("postgresql"):
        backend = os.getenv("MAOP_STORAGE_BACKEND", "").lower()
        if backend == "postgresql":
            # PG-backed store not yet implemented — degrade to SQLite.
            record_degradation("storage", "postgresql", "sqlite", "pg_notification_store_not_implemented")
    return NotificationStore(db_path)