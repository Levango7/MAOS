"""MAOP Enterprise License Validation.

Validates license keys for MAOP Enterprise edition. A license key is a
signed token containing customer info, edition, and expiry date.

Format:
    MAOP-ENT-{base64url(payload_json)}.{base64url(signature)}

The signature is Ed25519, verified against the public key bundled in
maop.enterprise.keys.public_key.pem.

Validation logic:
    1. Parse the key into payload + signature
    2. Verify the Ed25519 signature against the bundled public key
    3. Check that expires_at has not passed
    4. Machine fingerprint binding is ENFORCED when present in the license
       (fail-closed: a bound license on the wrong machine is rejected;
       legacy licenses without a fingerprint field skip this check)
    5. Check CRL (Certificate Revocation List) if MAOP_CRL_URL is configured

Limits enforcement (P0 #8 fix):
    ``max_users`` / ``features`` are parsed into :class:`LicenseInfo` and
    enforced via :func:`enforce_max_users` / :func:`feature_allowed`.
    Business layers (RBAC / quota / edition gates) must call these helpers;
    the validator itself does not know current user counts.

CRL (在线撤销) 支持:
    当设置了 MAOP_CRL_URL 环境变量时，LicenseValidator 会初始化
    CRLChecker，在签名+过期检查通过后查询 CRL。CRL 检查支持本地缓存
    和离线降级（详见 maop.enterprise.crl 模块）。

Degrade gracefully (2026-08-11 hardening — honor system REMOVED):
    - No license key configured → degrade to PERSONAL (previously honor-system
      granted enterprise; that was a trivial bypass and has been removed)
    - License key present but invalid → degrade to PERSONAL, log error
    - License key present and valid but modules tampered → degrade to PERSONAL
      (see verify_module_integrity below)
    - License key present and valid + modules intact → ENTERPRISE

Usage:
    validator = LicenseValidator()
    info = validator.validate_from_env()  # returns LicenseInfo or None
    # or
    info = validator.validate("MAOP-ENT-xxx.yyy")  # raises on invalid
"""

from __future__ import annotations

import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

__all__ = [
    "LicenseError",
    "LicenseExpiredError",
    "LicenseFingerprintError",
    "LicenseFormatError",
    "LicenseInfo",
    "LicenseLimitError",
    "LicenseSignatureError",
    "LicenseValidator",
    "compute_machine_fingerprint",
    "enforce_max_users",
    "feature_allowed",
]

# Grace period after expiry before hard degradation (days)
_GRACE_PERIOD_DAYS = 7

# Path to the bundled public key
_PUBLIC_KEY_PATH = Path(__file__).parent / "keys" / "public_key.pem"


class LicenseInfo(BaseModel):
    """Parsed and validated license information."""

    customer: str = Field(description="Customer/organization name")
    edition: str = Field(description="Licensed edition (should be 'enterprise')")
    issued_at: datetime = Field(description="When the license was issued")
    expires_at: datetime = Field(description="When the license expires")
    max_users: int | None = Field(default=None, description="Max concurrent users (None = unlimited)")
    fingerprint: str | None = Field(default=None, description="Optional machine fingerprint binding")
    features: list[str] | None = Field(default=None, description="Optional feature scope")
    license_id: str = Field(
        default="",
        description="Optional unique license ID (P1 #17) — CRL 吊销的精确匹配键，"
        "缺失时 CRL 回退按 customer 匹配（向后兼容）",
    )

    @property
    def is_expired(self) -> bool:
        """Check if the license has expired (before grace period)."""
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_in_grace_period(self) -> bool:
        """Check if the license is expired but within grace period."""
        now = datetime.now(timezone.utc)
        grace_end = self.expires_at + timedelta(days=_GRACE_PERIOD_DAYS)
        return self.expires_at < now <= grace_end


class LicenseError(Exception):
    """Base exception for license validation errors."""


class LicenseFormatError(LicenseError):
    """License key format is invalid (can't parse)."""


class LicenseSignatureError(LicenseError):
    """License signature verification failed (tampered or wrong key)."""


class LicenseExpiredError(LicenseError):
    """License has expired beyond the grace period."""

    def __init__(self, info: LicenseInfo) -> None:
        self.info = info
        super().__init__(
            f"License for '{info.customer}' expired on {info.expires_at.isoformat()} "
            f"(grace period of {_GRACE_PERIOD_DAYS} days has passed)"
        )


class LicenseFingerprintError(LicenseError):
    """Machine fingerprint binding check failed (license bound to another machine)."""


class LicenseLimitError(LicenseError):
    """A license limit (e.g. max_users) or feature scope was exceeded."""


def compute_machine_fingerprint() -> str:
    """计算本机指纹（SHA-256 hex），用于 license 机器绑定校验。

    组成：OS 机器 ID（Windows ``MachineGuid`` / Linux ``/etc/machine-id``）
    + ``platform.system()`` + ``platform.machine()``。无机器 ID 时回退到
    hostname。同一台机器上结果稳定；重装系统/更换硬件会改变指纹。
    """
    import hashlib
    import platform
    import socket

    machine_id = ""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as hk:
                machine_id = str(winreg.QueryValueEx(hk, "MachineGuid")[0])
        except Exception:
            machine_id = ""
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                machine_id = Path(p).read_text(encoding="utf-8").strip()
                if machine_id:
                    break
            except Exception as exc:
                logger.debug("[license] cannot read %s: %s", p, exc)
    if not machine_id:
        machine_id = socket.gethostname()
    raw = f"{machine_id}|{platform.system()}|{platform.machine()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def enforce_max_users(info: LicenseInfo, current_concurrent_users: int) -> None:
    """业务层强制 max_users 限制（P0 #8）。

    Parameters
    ----------
    info : LicenseInfo
        验证通过的 license 信息。
    current_concurrent_users : int
        当前并发用户数（由调用方统计，如活跃 session 数）。

    Raises
    ------
    LicenseLimitError
        当前用户数超过 license 的 max_users（``max_users=None`` 表示不限制）。
    """
    if info.max_users is not None and current_concurrent_users > info.max_users:
        raise LicenseLimitError(
            f"License for '{info.customer}' allows at most {info.max_users} "
            f"concurrent users, but {current_concurrent_users} are active"
        )


def feature_allowed(info: LicenseInfo, feature: str) -> bool:
    """检查 license 功能范围是否包含指定 feature（P0 #8）。

    ``features=None`` 表示不限制（全功能）；否则 feature 必须在列表内。
    业务层（RBAC/quota/edition gate）在启用企业特性前调用本函数。
    """
    if info.features is None:
        return True
    return feature in info.features


# L21/L22 (Phase R6): License 在线撤销（CRL）机制已实现。
# CRL 检查在签名验证 + 过期检查之后执行，仅当配置了 MAOP_CRL_URL 时启用。
# 实现细节：
#   1. HTTP 拉取 CRL 撤销列表（urllib，无额外依赖）
#   2. 本地缓存 + TTL（避免每次验证都网络请求）
#   3. 离线降级：拉取失败时使用缓存；无缓存时根据 MAOP_CRL_STRICT 决定行为
# 详见 maop.enterprise.crl 模块。


class LicenseValidator:
    """Validates MAOP Enterprise license keys.

    The validator loads the Ed25519 public key from the bundled
    ``keys/public_key.pem`` file. License keys are verified against
    this key; the corresponding private key is held by the MAOP
    commercial team and used to sign licenses at issuance time.

    If ``MAOP_CRL_URL`` is set, a :class:`CRLChecker` is initialized
    to perform online revocation checks after signature + expiry
    validation.
    """

    def __init__(self, public_key_path: Path | None = None) -> None:
        self._public_key_path = public_key_path or _PUBLIC_KEY_PATH
        self._public_key = self._load_public_key()
        self._crl_checker = self._init_crl_checker()

    def _load_public_key(self):
        """Load the Ed25519 public key from PEM file."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            if not self._public_key_path.exists():
                raise LicenseError(
                    f"Public key file not found: {self._public_key_path}. "
                    f"The maop-enterprise package may be corrupted."
                )
            key_data = self._public_key_path.read_bytes()
            public_key = serialization.load_pem_public_key(key_data)
            if not isinstance(public_key, Ed25519PublicKey):
                raise LicenseError(
                    f"Public key in {self._public_key_path} is not an Ed25519 key"
                )
            return public_key
        except LicenseError:
            raise
        except Exception as exc:
            raise LicenseError(f"Failed to load public key: {exc}") from exc

    def _init_crl_checker(self):
        """初始化 CRL 检查器（lazy，仅当配置了 MAOP_CRL_URL 时启用）。

        Returns:
            CRLChecker 实例或 None（未配置 CRL URL 时）
        """
        crl_url = os.getenv("MAOP_CRL_URL", "").strip()
        if not crl_url:
            return None
        try:
            from maop.enterprise.crl import CRLChecker

            checker = CRLChecker()
            logger.info(
                "[license] CRL revocation check enabled (url=%s, strict=%s)",
                checker.crl_url,
                checker.strict,
            )
            return checker
        except Exception as exc:
            logger.warning("[license] Failed to init CRL checker: %s", exc)
            return None

    def validate(
        self,
        license_key: str,
        *,
        expected_fingerprint: str | None = None,
    ) -> LicenseInfo:
        """Validate a license key and return its info.

        Parameters
        ----------
        license_key : str
            The license key string (format: MAOP-ENT-{payload}.{signature})
        expected_fingerprint : str | None
            机器指纹比对值（P0 #8）。license payload 含 ``fingerprint``
            字段时强制校验（fail-closed）：优先与本参数比对，未提供时
            用 :func:`compute_machine_fingerprint` 计算本机指纹比对。
            license 无 ``fingerprint`` 字段（旧版 license）时跳过。

        Returns
        -------
        LicenseInfo
            Parsed license metadata if valid.

        Raises
        ------
        LicenseFormatError
            If the key format is invalid (can't parse).
        LicenseSignatureError
            If the signature verification fails (tampered or wrong signing key).
        LicenseExpiredError
            If the license has expired beyond the grace period.
        LicenseFingerprintError
            If the license is bound to a machine fingerprint that does not
            match this machine (or ``expected_fingerprint``).
        LicenseRevokedError
            If the license has been revoked via CRL (only when MAOP_CRL_URL
            is configured).
        CRLError
            If strict CRL mode is enabled and the CRL cannot be obtained.
        """
        payload, signature = self._parse_key(license_key)
        self._verify_signature(payload, signature)
        info = self._parse_payload(payload)
        self._check_expiry(info)
        self._check_revocation(info)
        self._check_fingerprint(info, expected_fingerprint)
        return info

    @staticmethod
    def _check_fingerprint(
        info: LicenseInfo, expected_fingerprint: str | None = None
    ) -> None:
        """强制机器指纹绑定（fail-closed，P0 #8）。

        license 未携带 fingerprint 字段时跳过（兼容旧版 license）；
        携带时与 expected_fingerprint（或本机计算值）比对，不一致即拒绝。
        """
        if not info.fingerprint:
            return
        actual = expected_fingerprint or compute_machine_fingerprint()
        if actual != info.fingerprint:
            raise LicenseFingerprintError(
                f"License for '{info.customer}' is bound to machine fingerprint "
                f"{info.fingerprint[:12]}… but this machine presents {actual[:12]}… "
                f"(license cannot be copied to another machine)"
            )

    def validate_from_env(self) -> LicenseInfo | None:
        """Load and validate license from environment or file.

        Checks in order:
        1. ``MAOP_LICENSE_KEY`` environment variable
        2. ``data/license.key`` file (relative to MAOP_ROOT or cwd)

        Returns
        -------
        LicenseInfo or None
            ``None`` if no license key is configured (not an error —
            indicates honor-system mode). LicenseInfo if a key is
            present and valid.

        Raises
        ------
        LicenseError
            If a key is present but invalid (signature failure, expired, etc.)
        """
        key = self._load_key_from_env_or_file()
        if key is None:
            return None
        return self.validate(key)

    def _load_key_from_env_or_file(self) -> str | None:
        """Load license key from MAOP_LICENSE_KEY env or data/license.key file."""
        # 1. Environment variable
        key = os.getenv("MAOP_LICENSE_KEY", "").strip()
        if key:
            return key

        # 2. File (data/license.key)
        root = os.getenv("MAOP_ROOT_DIR") or os.getenv("MAOP_ROOT") or os.getcwd()
        key_file = Path(root) / "data" / "license.key"
        if key_file.exists():
            try:
                content = key_file.read_text(encoding="utf-8").strip()
                if content and not content.startswith("#"):
                    return content
            except Exception as exc:
                logger.warning("[license] Failed to read %s: %s", key_file, exc)

        return None

    @staticmethod
    def _parse_key(license_key: str) -> tuple[bytes, bytes]:
        """Parse a license key into (payload_bytes, signature_bytes).

        Format: MAOP-ENT-{base64url(payload)}.{base64url(signature)}
        """
        if not license_key:
            raise LicenseFormatError("Empty license key")

        key = license_key.strip()
        if not key.startswith("MAOP-ENT-"):
            raise LicenseFormatError(
                f"License key must start with 'MAOP-ENT-', got: {key[:20]}..."
            )

        body = key[len("MAOP-ENT-"):]
        if "." not in body:
            raise LicenseFormatError(
                "License key missing signature separator '.'"
            )

        payload_b64, sig_b64 = body.rsplit(".", 1)
        try:
            # Use URL-safe base64 decoder, add padding if needed
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
            signature = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception as exc:
            raise LicenseFormatError(f"Failed to decode base64: {exc}") from exc

        if len(signature) != 64:
            raise LicenseFormatError(
                f"Ed25519 signature must be 64 bytes, got {len(signature)}"
            )

        return payload_bytes, signature

    def _verify_signature(self, payload: bytes, signature: bytes) -> None:
        """Verify the Ed25519 signature."""
        try:
            self._public_key.verify(signature, payload)
        except Exception as exc:
            raise LicenseSignatureError(
                "License signature verification failed — the key may be "
                "tampered, expired, or issued by an unauthorized party"
            ) from exc

    @staticmethod
    def _parse_payload(payload: bytes) -> LicenseInfo:
        """Parse the JSON payload into LicenseInfo."""
        try:
            data = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise LicenseFormatError(f"Failed to parse payload JSON: {exc}") from exc

        # Validate required fields
        required = ["customer", "edition", "issued_at", "expires_at"]
        for field in required:
            if field not in data:
                raise LicenseFormatError(f"Payload missing required field: {field}")

        # Parse datetime fields (support ISO format with or without timezone)
        for dt_field in ["issued_at", "expires_at"]:
            val = data[dt_field]
            if isinstance(val, str):
                # Handle 'Z' suffix
                if val.endswith("Z"):
                    val = val[:-1] + "+00:00"
                data[dt_field] = datetime.fromisoformat(val)
            elif isinstance(val, datetime):
                pass
            else:
                raise LicenseFormatError(
                    f"Field '{dt_field}' must be ISO datetime, got {type(val).__name__}"
                )

        # Ensure timezone-aware (assume UTC if naive)
        for dt_field in ["issued_at", "expires_at"]:
            if data[dt_field].tzinfo is None:
                data[dt_field] = data[dt_field].replace(tzinfo=timezone.utc)

        return LicenseInfo(**data)

    @staticmethod
    def _check_expiry(info: LicenseInfo) -> None:
        """Check if the license is still valid (within grace period)."""
        if info.is_in_grace_period:
            logger.warning(
                "[license] License for '%s' is in grace period "
                "(expired %s, grace ends in %d days)",
                info.customer,
                info.expires_at.isoformat(),
                _GRACE_PERIOD_DAYS - (datetime.now(timezone.utc) - info.expires_at).days,
            )
        elif info.is_expired:
            raise LicenseExpiredError(info)

    def _check_revocation(self, info: LicenseInfo) -> None:
        """检查 license 是否被撤销（CRL）。仅当配置了 CRL URL 时启用。"""
        if self._crl_checker:
            self._crl_checker.check_license(info)


# ── Module integrity self-verification (anti-tamper hardening) ────────────

_MANIFEST_PATH = Path(__file__).parent / "_integrity_manifest.json"


class ModuleTamperError(LicenseError):
    """Enterprise module files have been modified after signing."""


def verify_module_integrity(*, strict: bool | None = None) -> tuple[bool, str]:
    """Verify enterprise modules haven't been tampered with.

    Reads ``_integrity_manifest.json`` (created at sign-time by
    ``scripts/sign_enterprise_modules.py``) and checks every listed
    file's SHA-256, then verifies the manifest's own Ed25519 signature
    against the bundled public key.

    Parameters
    ----------
    strict : bool | None
        If True, any anomaly raises :class:`ModuleTamperError`.
        If False, anomalies return ``(False, reason)`` without raising.
        Either way, the result is logged. When ``strict`` is None, it
        defaults to True in production (``MAOP_ENV=production``) and
        False otherwise.

    Returns
    -------
    (ok, reason):
        ``ok=True`` → all modules verified against manifest.
        ``ok=False`` → manifest missing/invalid/files modified; ``reason``
        explains what failed.

    Security model
    --------------
    This check assumes the * attacker modifies enterprise module files
    *after* license activation. It catches:
      - Direct edits to rbac.py / audit.py / etc.
      - Manifest deletion (raises tamper-suspected in strict mode).
      - Manifest signature forgery (needs the private key; without it,
        signature verification fails).

    It does NOT catch:
      - Patching this very function out of ``license.py`` (attacker must
        also edit the public key, breaking normal license validation).
      - Memory-patching the module after import (defeats the point of
        file-level signing).

    This is a **raising-the-bar** control, not absolute protection. Pair
    it with the PyArmor obfuscation pipeline for stronger guarantees.

    Environment variables
    ---------------------
    ``MAOP_SKIP_INTEGRITY=1``: skip the check entirely (test/dev escape hatch,
    e.g. when the on-disk manifest was signed with a production key but tests
    patch ``_PUBLIC_KEY_PATH`` to a throwaway keypair). Must NOT be set in
    production — the variable is honored silently by design so tests can
    enable it without logging noise, but you can audit it externally.
    """
    if strict is None:
        strict = os.getenv("MAOP_ENV", "development").lower() == "production"

    # Test escape hatch: skip manifest verification if explicitly requested.
    # This is intentionally silent — tests enable it to isolate license-key
    # verification from code-signing concerns.
    if os.getenv("MAOP_SKIP_INTEGRITY", "").strip().lower() in ("1", "true", "yes"):
        return True, "skipped"

    def _fail(reason: str, exc: Exception | None = None) -> tuple[bool, str]:
        msg = f"enterprise module integrity check failed: {reason}"
        logger.error("[integrity] %s", msg)
        if strict:
            if exc:
                raise ModuleTamperError(msg) from exc
            raise ModuleTamperError(msg)
        return False, reason

    if not _MANIFEST_PATH.exists():
        return _fail(f"manifest not found: {_MANIFEST_PATH}")

    try:
        import json as _json
        manifest = _json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return _fail(f"manifest unreadable: {exc}", exc)

    expected_sig_b64 = manifest.get("signature")
    files = manifest.get("files", {})
    if not expected_sig_b64 or not files:
        return _fail("manifest malformed (missing 'signature' or 'files')")

    # 1. Verify manifest signature over canonical payload
    # NOTE: reuse LicenseValidator to load the public key so tests that patch
    # ``maop.enterprise.license._PUBLIC_KEY_PATH`` also patch this verification.
    try:
        import base64 as _b64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub = LicenseValidator()._public_key
        if not isinstance(pub, Ed25519PublicKey):
            return _fail("bundled public key is not Ed25519")

        # Rebuild canonical payload EXACTLY as the signing tool did
        signed_at = manifest.get("signed_at", "")
        payload = _json.dumps(
            {
                "files": files,
                "signed_at": signed_at,
                "tool": "sign_enterprise_modules.py",
                "version": manifest.get("version", 1),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = _b64.urlsafe_b64decode(expected_sig_b64 + "==")
        pub.verify(signature, payload)
    except ModuleTamperError:
        raise
    except Exception as exc:
        return _fail(f"manifest signature verification failed: {exc}", exc)

    # 2. Hash-check each declared module
    import hashlib as _hashlib

    repo_root = _MANIFEST_PATH.parent  # maop/enterprise/
    tampered: list[str] = []
    for rel_filename, expected_hash in files.items():
        target = repo_root / rel_filename.replace("maop/enterprise/", "")
        if not target.exists():
            tampered.append(f"{rel_filename} (missing)")
            continue
        actual = _hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected_hash:
            tampered.append(rel_filename)

    if tampered:
        return _fail(f"modified modules detected: {tampered}")

    logger.info("[integrity] %d enterprise modules verified", len(files))
    return True, "ok"
