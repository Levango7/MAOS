"""MAOP Enterprise License Management — issuance, lifecycle, audit.

This module implements the License Management backend (PRD:
``docs/prd-license-management.md``). It provides a CRUD + lifecycle
manager for issued licenses, backed by SQLite (default) or PostgreSQL
(enterprise) and an append-only audit log.

Design decisions
----------------
* **Signing algorithm**: Ed25519 (not RSA). The existing
  :class:`maop.enterprise.license.LicenseValidator` already uses
  Ed25519 with a bundled public key; issuing RSA-signed licenses would
  be unverifiable by the runtime validator. Ed25519 is also faster,
  produces 64-byte signatures (vs 256+ for RSA-2048), and is the
  algorithm documented in ``docs/enterprise/license-issuance-guide.md``.
* **Storage**: SQLite by default (personal/dev), PostgreSQL when
  ``FeatureFlag.LICENSE_MANAGEMENT`` + PG backend is available. The
  PgLicenseStore in ``pg_persist.py`` handles the PG path; this module
  owns the SQLite path and the in-memory business logic.
* **Audit log**: every state-changing operation appends a row to
  ``license_audit_logs`` (PG) or the SQLite mirror, providing a
  tamper-evident trail of issuance / revocation / renewal / deletion.

Public API
----------
* :class:`LicenseRecord` — Pydantic model for a stored license
* :class:`LicenseAuditEntry` — Pydantic model for an audit log row
* :class:`LicenseManager` — the manager class used by the router
* Request/response models: :class:`LicenseCreateRequest`,
  :class:`LicenseUpdateRequest`, :class:`LicenseRenewRequest`,
  :class:`LicenseRevokeRequest`, :class:`LicenseValidateRequest`
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

__all__ = [
    "LicenseAuditEntry",
    "LicenseCreateRequest",
    "LicenseManager",
    "LicenseNotFoundError",
    "LicenseRecord",
    "LicenseRenewRequest",
    "LicenseRevokeRequest",
    "LicenseUpdateRequest",
    "LicenseValidateRequest",
    "LicenseValidationError",
]

# Grace period after expiry before the license is considered hard-expired.
GRACE_PERIOD_DAYS = 7

# Default SQLite DB path (under MAOP_DATA_DIR or MAOP_ROOT/data).
_DEFAULT_DB_FILENAME = "licenses.db"


# ── Pydantic models ────────────────────────────────────────────────


class LicenseRecord(BaseModel):
    """A stored license record (one row in the ``licenses`` table)."""

    license_id: str = Field(description="UUID identifying this license")
    customer: str = Field(description="Customer / organization name")
    edition: str = Field(default="enterprise", description="Licensed edition")
    max_users: int | None = Field(default=None, description="Max concurrent users (None = unlimited)")
    fingerprint: str | None = Field(default=None, description="Optional machine fingerprint binding")
    features: list[str] = Field(default_factory=list, description="Feature scope")
    status: str = Field(default="active", description="active / revoked / expired")
    issued_at: float = Field(description="Issuance timestamp (Unix epoch seconds)")
    expires_at: float = Field(description="Expiry timestamp (Unix epoch seconds)")
    revoked_at: float | None = Field(default=None, description="Revocation timestamp, if revoked")
    revoked_reason: str = Field(default="", description="Reason for revocation")
    license_key: str = Field(description="The signed license key string (MAOP-ENT-...)")
    issued_by: str = Field(default="", description="Who issued the license")
    notes: str = Field(default="", description="Free-form notes")
    created_at: float = Field(default=0.0, description="Row creation timestamp")
    updated_at: float = Field(default=0.0, description="Row last-update timestamp")
    deleted_at: float | None = Field(
        default=None,
        description="Soft-deletion timestamp (P1 #14); row + audit logs retained",
    )

    @property
    def is_expired(self) -> bool:
        """Whether the license has passed its expiry date."""
        return time.time() > self.expires_at

    @property
    def is_in_grace_period(self) -> bool:
        """Whether the license is expired but within the grace period."""
        now = time.time()
        grace_end = self.expires_at + GRACE_PERIOD_DAYS * 86400
        return self.expires_at < now <= grace_end

    @property
    def is_revoked(self) -> bool:
        """Whether the license has been revoked."""
        return self.status == "revoked"

    @property
    def is_active(self) -> bool:
        """Whether the license is currently active (not revoked, not expired)."""
        if self.status != "active":
            return False
        now = time.time()
        grace_end = self.expires_at + GRACE_PERIOD_DAYS * 86400
        return now <= grace_end


class LicenseAuditEntry(BaseModel):
    """One row in the ``license_audit_logs`` table."""

    log_id: str
    license_id: str
    action: str = Field(description="created / validated / revoked / renewed / deleted / updated")
    actor: str = ""
    timestamp: float
    detail: str = ""
    ip_address: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Request models (used by the router) ────────────────────────────


class LicenseCreateRequest(BaseModel):
    """Request body for POST /api/licenses/create."""

    customer: str = Field(min_length=1, max_length=200, description="Customer name")
    expires_at: str = Field(description="ISO 8601 datetime or YYYY-MM-DD")
    max_users: int | None = Field(default=None, ge=1, description="Max concurrent users")
    fingerprint: str | None = Field(default=None, max_length=200, description="Machine fingerprint")
    features: list[str] = Field(default_factory=list, description="Feature scope")
    issued_by: str = Field(default="", max_length=100, description="Issuer name")
    notes: str = Field(default="", max_length=1000, description="Free-form notes")


class LicenseUpdateRequest(BaseModel):
    """Request body for PATCH /api/licenses/{license_id}."""

    customer: str | None = Field(default=None, min_length=1, max_length=200)
    max_users: int | None = Field(default=None, ge=1)
    fingerprint: str | None = Field(default=None, max_length=200)
    features: list[str] | None = None
    notes: str | None = Field(default=None, max_length=1000)


class LicenseRenewRequest(BaseModel):
    """Request body for POST /api/licenses/{license_id}/renew."""

    new_expires_at: str = Field(description="New expiry (ISO 8601 or YYYY-MM-DD)")
    actor: str = Field(default="", max_length=100)


class LicenseRevokeRequest(BaseModel):
    """Request body for POST /api/licenses/{license_id}/revoke."""

    reason: str = Field(default="", max_length=500)
    actor: str = Field(default="", max_length=100)


class LicenseValidateRequest(BaseModel):
    """Request body for POST /api/licenses/validate."""

    license_key: str = Field(description="The license key to validate")


# ── Exceptions ─────────────────────────────────────────────────────


class LicenseNotFoundError(Exception):
    """Raised when a license_id is not found in the store."""


class LicenseValidationError(Exception):
    """Raised when a license key fails validation (signature/expiry/revocation)."""


# ── LicenseManager ─────────────────────────────────────────────────


class LicenseManager:
    """Manages the full lifecycle of MAOP Enterprise licenses.

    Responsibilities:
      * Generate Ed25519-signed license keys
      * Persist license records + audit logs (SQLite or PostgreSQL)
      * Validate, revoke, renew, update, delete licenses
      * Query audit history

    Parameters
    ----------
    private_key_path
        Path to the Ed25519 private key PEM used for signing. If None,
        the manager runs in **verification-only mode**: query/validate
        work, but ``create_license`` raises (P1 #15 — 不再生成内存临时
        密钥对，避免签发重启后无法验证的 license).
    public_key_path
        Path to the Ed25519 public key PEM used for verification. If
        None, the in-memory public key paired with ``private_key_path``
        is used. When ``private_key_path`` is None and this is None,
        the bundled ``maop.enterprise.keys.public_key.pem`` is used for
        verification only (no signing possible).
    db_path
        Path to the SQLite DB file. If None, uses
        ``{MAOP_DATA_DIR or MAOP_ROOT/data}/licenses.db``. Ignored when
        PostgreSQL is available via :class:`PgLicenseStore`.
    """

    def __init__(
        self,
        *,
        private_key_path: Path | None = None,
        public_key_path: Path | None = None,
        db_path: Path | None = None,
    ) -> None:
        self._private_key = self._load_private_key(private_key_path)
        self._public_key, self._public_key_source = self._load_public_key(
            public_key_path, private_key_path, self._private_key
        )
        self._db_path = db_path or self._default_db_path()
        self._pg: Any = None
        try:
            from maop.enterprise.pg_persist import PgLicenseStore
            pg = PgLicenseStore()
            if pg.available:
                self._pg = pg
                logger.info("[license_mgr] PostgreSQL backend active")
        except Exception as exc:
            logger.debug("[license_mgr] PG store unavailable: %s", exc)
        if self._pg is None:
            self._ensure_sqlite_schema()

    # ── Key management ─────────────────────────────────────────────

    @staticmethod
    def _load_private_key(path: Path | None) -> Any:
        """Load the Ed25519 private key for signing.

        P1 #15 fix: ``path=None`` 时返回 None（仅验证模式）。旧实现在
        此时生成内存临时密钥对——签发的 license 重启后无法验证，且与
        打包公钥不匹配，等于静默产出无效 license。签发必须显式提供私钥。
        """
        from cryptography.hazmat.primitives import serialization

        if path is None:
            return None
        key_data = path.read_bytes()
        # Strip optional header comment line (e.g. "DEVELOPMENT PRIVATE KEY ...")
        if not key_data.strip().startswith(b"-----BEGIN"):
            lines = key_data.split(b"\n")
            key_data = b"\n".join(lines[1:])
        return serialization.load_pem_private_key(key_data, password=None)

    @staticmethod
    def _load_public_key(
        path: Path | None,
        private_key_path: Path | None,
        loaded_private_key: Any,
    ) -> tuple[Any, str]:
        """Load the Ed25519 public key for verification.

        Returns (public_key, source_description).

        Resolution order:
          1. Explicit ``path`` → load that PEM file.
          2. ``private_key_path`` given → re-load it and derive the paired
             public key (ensures sign/verify use the same keypair).
          3. Fall back to the bundled ``maop.enterprise.keys/public_key.pem``
             (verification-only mode — signing disabled, useful for
             read-only inspection of licenses signed by the production key).

        P1 #15 fix: 不再回退到随机生成的内存公钥——那会让验签静默使用
        错误的密钥。打包公钥缺失时直接报错（fail-closed）。
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if path is not None:
            key_data = path.read_bytes()
            pub = serialization.load_pem_public_key(key_data)
            if not isinstance(pub, Ed25519PublicKey):
                raise LicenseValidationError(f"Public key in {path} is not Ed25519")
            return pub, str(path)
        if private_key_path is not None:
            priv = LicenseManager._load_private_key(private_key_path)
            return priv.public_key(), f"paired-with:{private_key_path}"
        # Verification-only: bundled public key.
        bundled = Path(__file__).parent / "keys" / "public_key.pem"
        if bundled.exists():
            pub = serialization.load_pem_public_key(bundled.read_bytes())
            if isinstance(pub, Ed25519PublicKey):
                return pub, str(bundled)
        raise LicenseValidationError(
            "No public key available for license verification "
            f"(expected bundled key at {bundled})"
        )

    # ── DB helpers ─────────────────────────────────────────────────

    @staticmethod
    def _default_db_path() -> Path:
        data_dir = os.getenv("MAOP_DATA_DIR") or os.getenv("MAOP_ROOT_DIR") or os.getenv("MAOP_ROOT") or os.getcwd()
        p = Path(data_dir) / "data" / _DEFAULT_DB_FILENAME
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _ensure_sqlite_schema(self) -> None:
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    license_id TEXT PRIMARY KEY,
                    customer TEXT NOT NULL,
                    edition TEXT NOT NULL DEFAULT 'enterprise',
                    max_users INTEGER,
                    fingerprint TEXT,
                    features TEXT DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'active',
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at REAL,
                    revoked_reason TEXT DEFAULT '',
                    license_key TEXT NOT NULL,
                    issued_by TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    created_at REAL DEFAULT 0,
                    updated_at REAL DEFAULT 0,
                    deleted_at REAL
                )
            """)
            # P1 #14: 旧库升级 —— 补 deleted_at 列（已存在则忽略错误）
            try:
                conn.execute("ALTER TABLE licenses ADD COLUMN deleted_at REAL")
            except Exception:
                logger.debug("deleted_at column already exists", exc_info=True)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS license_audit_logs (
                    log_id TEXT PRIMARY KEY,
                    license_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    detail TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (license_id) REFERENCES licenses(license_id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_license ON license_audit_logs(license_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_action ON license_audit_logs(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_license_audit_timestamp ON license_audit_logs(timestamp)")

    def _sqlite_connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    # ── Signing ────────────────────────────────────────────────────

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        """Sign a payload dict and return the full license key string.

        Format: ``MAOP-ENT-{base64url(payload_json)}.{base64url(signature)}``

        Raises :class:`LicenseValidationError` when no private key was
        configured (verification-only mode, P1 #15).
        """
        if self._private_key is None:
            raise LicenseValidationError(
                "License issuance requires a private signing key — construct "
                "LicenseManager(private_key_path=...). Verification-only mode "
                "cannot sign licenses."
            )
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = self._private_key.sign(payload_json)
        payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode("ascii")
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        return f"MAOP-ENT-{payload_b64}.{sig_b64}"

    def _verify_signature(self, license_key: str) -> dict[str, Any]:
        """Verify a license key's signature and return its payload.

        Raises :class:`LicenseValidationError` on any failure.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(self._public_key, Ed25519PublicKey):
            raise LicenseValidationError("Loaded public key is not Ed25519")
        if not license_key or not license_key.startswith("MAOP-ENT-"):
            raise LicenseValidationError("License key must start with 'MAOP-ENT-'")
        body = license_key[len("MAOP-ENT-"):]
        if "." not in body:
            raise LicenseValidationError("License key missing signature separator '.'")
        payload_b64, sig_b64 = body.rsplit(".", 1)
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
            signature = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception as exc:
            raise LicenseValidationError(f"Failed to decode base64: {exc}") from exc
        if len(signature) != 64:
            raise LicenseValidationError(f"Ed25519 signature must be 64 bytes, got {len(signature)}")
        try:
            self._public_key.verify(signature, payload_bytes)
        except Exception as exc:
            raise LicenseValidationError("Signature verification failed") from exc
        try:
            result: dict[str, Any] = json.loads(payload_bytes.decode("utf-8"))
            return result
        except Exception as exc:
            raise LicenseValidationError(f"Failed to parse payload JSON: {exc}") from exc

    # ── Public API ─────────────────────────────────────────────────

    def create_license(
        self,
        *,
        customer: str,
        expires_at: str,
        max_users: int | None = None,
        fingerprint: str | None = None,
        features: list[str] | None = None,
        issued_by: str = "",
        notes: str = "",
    ) -> LicenseRecord:
        """Issue a new license, sign it, persist, and audit-log the creation."""
        expires_dt = self._parse_datetime(expires_at)
        now = time.time()
        issued_dt = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "customer": customer,
            "edition": "enterprise",
            "issued_at": issued_dt.isoformat(),
            "expires_at": expires_dt.isoformat(),
        }
        if max_users is not None:
            payload["max_users"] = max_users
        if fingerprint:
            payload["fingerprint"] = fingerprint
        if features:
            payload["features"] = list(features)
        license_key = self._sign_payload(payload)
        license_id = str(uuid.uuid4())
        record = LicenseRecord(
            license_id=license_id,
            customer=customer,
            edition="enterprise",
            max_users=max_users,
            fingerprint=fingerprint,
            features=list(features or []),
            status="active",
            issued_at=now,
            expires_at=expires_dt.timestamp(),
            license_key=license_key,
            issued_by=issued_by,
            notes=notes,
            created_at=now,
            updated_at=now,
        )
        self._save_record(record)
        self._log_audit(
            license_id=license_id,
            action="created",
            actor=issued_by,
            detail=f"License issued for '{customer}', expires {expires_dt.isoformat()}",
        )
        logger.info("[license_mgr] Created license_id=%s customer=%s", license_id, customer)
        return record

    def list_licenses(self, status: str = "") -> list[LicenseRecord]:
        """Return all licenses, optionally filtered by status.

        P1 #14: 默认列表排除软删除的 license（``status='deleted'``）；
        显式传 ``status='deleted'`` 时可查看已删除记录。
        """
        if self._pg:
            rows = self._pg.load_licenses(status=status)
        else:
            with self._sqlite_connect() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM licenses WHERE status=? ORDER BY created_at DESC",
                        (status,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM licenses WHERE status != 'deleted' "
                        "ORDER BY created_at DESC"
                    ).fetchall()
            rows = [dict(r) for r in rows]
        return [self._row_to_record(r) for r in rows]

    def get_license(self, license_id: str) -> LicenseRecord:
        """Return a single license by ID. Raises if not found."""
        row = self._load_record(license_id)
        if row is None:
            raise LicenseNotFoundError(f"License '{license_id}' not found")
        return row

    def validate_license(self, license_key: str) -> dict[str, Any]:
        """Validate a license key (signature + expiry + revocation).

        Returns a dict with ``valid``, ``reason``, and parsed ``info``.
        Never raises on validation failure — returns ``valid=False`` with
        a human-readable reason. Raises :class:`LicenseValidationError`
        only on internal errors (e.g. key not loadable).
        """
        try:
            payload = self._verify_signature(license_key)
        except LicenseValidationError as exc:
            return {"valid": False, "reason": f"signature_invalid: {exc}", "info": None}
        expires_raw = payload.get("expires_at")
        if not expires_raw:
            return {"valid": False, "reason": "payload_missing_expires_at", "info": payload}
        try:
            expires_dt = self._parse_datetime(expires_raw)
        except Exception as exc:
            return {"valid": False, "reason": f"invalid_expires_at: {exc}", "info": payload}
        now = time.time()
        grace_end = expires_dt.timestamp() + GRACE_PERIOD_DAYS * 86400
        if now > grace_end:
            return {"valid": False, "reason": "expired", "info": payload}
        # Check revocation in our store (match by license_key).
        revoked = self._is_key_revoked(license_key)
        if revoked:
            return {"valid": False, "reason": f"revoked: {revoked}", "info": payload}
        in_grace = expires_dt.timestamp() < now <= grace_end
        return {
            "valid": True,
            "reason": "in_grace_period" if in_grace else "ok",
            "info": payload,
        }

    def revoke_license(self, license_id: str, *, reason: str = "", actor: str = "") -> LicenseRecord:
        """Mark a license as revoked. Idempotent on already-revoked licenses."""
        record = self.get_license(license_id)
        if record.status == "revoked":
            return record
        now = time.time()
        record.status = "revoked"
        record.revoked_at = now
        record.revoked_reason = reason
        record.updated_at = now
        self._save_record(record)
        self._log_audit(
            license_id=license_id,
            action="revoked",
            actor=actor,
            detail=f"License revoked. Reason: {reason}" if reason else "License revoked",
        )
        logger.warning("[license_mgr] Revoked license_id=%s reason=%s", license_id, reason)
        return record

    def renew_license(self, license_id: str, *, new_expires_at: str, actor: str = "") -> LicenseRecord:
        """Renew a license: re-sign with a new expiry, keep the same ID.

        The old license key is replaced; the audit log records the renewal.
        """
        record = self.get_license(license_id)
        new_expires_dt = self._parse_datetime(new_expires_at)
        issued_dt = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "customer": record.customer,
            "edition": record.edition,
            "issued_at": issued_dt.isoformat(),
            "expires_at": new_expires_dt.isoformat(),
        }
        if record.max_users is not None:
            payload["max_users"] = record.max_users
        if record.fingerprint:
            payload["fingerprint"] = record.fingerprint
        if record.features:
            payload["features"] = list(record.features)
        new_key = self._sign_payload(payload)
        now = time.time()
        record.license_key = new_key
        record.issued_at = now
        record.expires_at = new_expires_dt.timestamp()
        record.status = "active"
        record.revoked_at = None
        record.revoked_reason = ""
        record.updated_at = now
        self._save_record(record)
        self._log_audit(
            license_id=license_id,
            action="renewed",
            actor=actor,
            detail=f"License renewed, new expiry {new_expires_dt.isoformat()}",
        )
        logger.info("[license_mgr] Renewed license_id=%s new_expiry=%s", license_id, new_expires_dt.isoformat())
        return record

    def update_license(self, license_id: str, **kwargs: Any) -> LicenseRecord:
        """Update editable metadata fields (customer, max_users, fingerprint, features, notes).

        Does NOT change the license key or expiry — use ``renew_license`` for that.
        """
        record = self.get_license(license_id)
        allowed = {"customer", "max_users", "fingerprint", "features", "notes"}
        changed: list[str] = []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                setattr(record, k, v)
                changed.append(k)
        if not changed:
            return record
        record.updated_at = time.time()
        self._save_record(record)
        self._log_audit(
            license_id=license_id,
            action="updated",
            detail=f"Updated fields: {', '.join(changed)}",
        )
        return record

    def delete_license(self, license_id: str, *, actor: str = "") -> bool:
        """Soft-delete a license (P1 #14). Returns True if deleted.

        旧实现物理删除 license 行 **及其全部审计日志**，销毁了合规
        证据链。现改为软删除：``status='deleted'`` + ``deleted_at`` 时间戳，
        license 行与 ``license_audit_logs`` 全部保留作为审计证据。
        默认列表（``list_licenses()``）不再显示已删除 license。
        """
        # Verify existence first.
        self.get_license(license_id)
        now = time.time()
        if self._pg:
            self._pg.soft_delete_license(license_id, now)
        else:
            with self._sqlite_connect() as conn:
                conn.execute(
                    "UPDATE licenses SET status='deleted', deleted_at=?, updated_at=? "
                    "WHERE license_id=?",
                    (now, now, license_id),
                )
        # 审计日志保留（不再删除），仅追加 deleted 记录
        self._log_audit(
            license_id=license_id,
            action="deleted",
            actor=actor,
            detail="License soft-deleted (record and audit logs retained)",
        )
        logger.info("[license_mgr] Soft-deleted license_id=%s", license_id)
        return True

    def get_audit_logs(
        self,
        license_id: str = "",
        action: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> list[LicenseAuditEntry]:
        """Return audit log entries, optionally filtered."""
        if self._pg:
            rows = self._pg.load_audit_logs(license_id=license_id, action=action, limit=limit, offset=offset)
        else:
            with self._sqlite_connect() as conn:
                clauses: list[str] = []
                params: list[Any] = []
                if license_id:
                    clauses.append("license_id=?")
                    params.append(license_id)
                if action:
                    clauses.append("action=?")
                    params.append(action)
                where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
                params.extend([limit, offset])
                rows = conn.execute(
                    f"SELECT * FROM license_audit_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    tuple(params),
                ).fetchall()
            rows = [dict(r) for r in rows]
        return [self._row_to_audit(r) for r in rows]

    # ── Internal persistence helpers ───────────────────────────────

    def _save_record(self, record: LicenseRecord) -> None:
        data = record.model_dump()
        if self._pg:
            self._pg.save_license(data)
            return
        with self._sqlite_connect() as conn:
            conn.execute(
                """INSERT INTO licenses
                   (license_id, customer, edition, max_users, fingerprint, features, status,
                    issued_at, expires_at, revoked_at, revoked_reason, license_key,
                    issued_by, notes, created_at, updated_at, deleted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(license_id) DO UPDATE SET
                     customer=excluded.customer, edition=excluded.edition,
                     max_users=excluded.max_users, fingerprint=excluded.fingerprint,
                     features=excluded.features, status=excluded.status,
                     issued_at=excluded.issued_at, expires_at=excluded.expires_at,
                     revoked_at=excluded.revoked_at, revoked_reason=excluded.revoked_reason,
                     license_key=excluded.license_key, issued_by=excluded.issued_by,
                     notes=excluded.notes, updated_at=excluded.updated_at,
                     deleted_at=excluded.deleted_at""",
                (data["license_id"], data["customer"], data["edition"],
                 data["max_users"], data["fingerprint"], json.dumps(data["features"]),
                 data["status"], data["issued_at"], data["expires_at"],
                 data["revoked_at"], data["revoked_reason"], data["license_key"],
                 data["issued_by"], data["notes"], data["created_at"], data["updated_at"],
                 data["deleted_at"]),
            )

    def _load_record(self, license_id: str) -> LicenseRecord | None:
        if self._pg:
            row = self._pg.load_license(license_id)
        else:
            with self._sqlite_connect() as conn:
                row = conn.execute(
                    "SELECT * FROM licenses WHERE license_id=?", (license_id,)
                ).fetchone()
            row = dict(row) if row else None
        if row is None:
            return None
        return self._row_to_record(row)

    def _is_key_revoked(self, license_key: str) -> str:
        """Return the revocation reason if the key is revoked, else empty string."""
        if self._pg:
            rows = self._pg.load_licenses(status="revoked")
        else:
            with self._sqlite_connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM licenses WHERE status='revoked'"
                ).fetchall()
            rows = [dict(r) for r in rows]
        for r in rows:
            if r.get("license_key") == license_key:
                return r.get("revoked_reason", "") or "revoked"
        return ""

    def _log_audit(
        self,
        *,
        license_id: str,
        action: str,
        actor: str = "",
        detail: str = "",
        ip_address: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "log_id": str(uuid.uuid4()),
            "license_id": license_id,
            "action": action,
            "actor": actor,
            "timestamp": time.time(),
            "detail": detail,
            "ip_address": ip_address,
            "metadata": metadata or {},
        }
        if self._pg:
            self._pg.save_audit_log(event)
            return
        with self._sqlite_connect() as conn:
            conn.execute(
                """INSERT INTO license_audit_logs
                   (log_id, license_id, action, actor, timestamp, detail, ip_address, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event["log_id"], event["license_id"], event["action"],
                 event["actor"], event["timestamp"], event["detail"],
                 event["ip_address"], json.dumps(event["metadata"])),
            )

    # ── Row conversion ─────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: dict[str, Any]) -> LicenseRecord:
        features = row.get("features", [])
        if isinstance(features, str):
            try:
                features = json.loads(features)
            except Exception:
                features = []
        return LicenseRecord(
            license_id=row["license_id"],
            customer=row["customer"],
            edition=row.get("edition", "enterprise"),
            max_users=row.get("max_users"),
            fingerprint=row.get("fingerprint"),
            features=features if isinstance(features, list) else [],
            status=row.get("status", "active"),
            issued_at=row.get("issued_at", 0.0),
            expires_at=row.get("expires_at", 0.0),
            revoked_at=row.get("revoked_at"),
            revoked_reason=row.get("revoked_reason", ""),
            license_key=row["license_key"],
            issued_by=row.get("issued_by", ""),
            notes=row.get("notes", ""),
            created_at=row.get("created_at", 0.0),
            updated_at=row.get("updated_at", 0.0),
            deleted_at=row.get("deleted_at"),
        )

    @staticmethod
    def _row_to_audit(row: dict[str, Any]) -> LicenseAuditEntry:
        meta = row.get("metadata", {})
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        return LicenseAuditEntry(
            log_id=row["log_id"],
            license_id=row["license_id"],
            action=row["action"],
            actor=row.get("actor", ""),
            timestamp=row.get("timestamp", 0.0),
            detail=row.get("detail", ""),
            ip_address=row.get("ip_address", ""),
            metadata=meta if isinstance(meta, dict) else {},
        )

    # ── Datetime parsing ───────────────────────────────────────────

    @staticmethod
    def _parse_datetime(value: str | datetime) -> datetime:
        """Parse an ISO 8601 datetime or YYYY-MM-DD string into a UTC datetime.

        YYYY-MM-DD is interpreted as that day at 23:59:59 UTC (end of day),
        matching the convention in ``scripts/generate_license.py``.
        """
        if isinstance(value, datetime):
            dt = value
        else:
            s = value.strip()
            # YYYY-MM-DD → end of that day in UTC
            if len(s) == 10 and s.count("-") == 2 and "T" not in s:
                s = s + "T23:59:59+00:00"
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)