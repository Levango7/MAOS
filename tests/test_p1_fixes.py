"""Regression tests for the Phase 2 (P1) fixes.

Every persistence-related test isolates its database into ``tmp_path``
(explicit ``db_path`` or ``MAOP_DATA_DIR``) so the repo's ``data/``
directory is never polluted.

Covered fixes:
  #11 audit SQLite fallback        #17 CRL license_id + signature
  #12 RBAC SQLite fallback         #19 sso_store encryption at rest
  #13 SSO session/state persist    #20 quota atomic consume + clamp
  #14 license soft delete          #22 notification stats types
  #15 verification-only mode       #23 tenant update whitelist
  #16 (script guard, manual)       #24 HA node auth hook
                                   #25 TLS cert/key match
"""
from __future__ import annotations

import base64
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── #11: audit SQLite fallback ──────────────────────────────────────


def test_audit_sqlite_fallback_persists_events(
    tmp_path, monkeypatch, enterprise_edition
):
    monkeypatch.setenv("MAOP_DATA_DIR", str(tmp_path))
    from maop.enterprise.audit import AuditAction, EnterpriseAuditLogger

    audit = EnterpriseAuditLogger()
    assert audit._sqlite is not None and audit._sqlite.available
    assert audit._pg is None  # no PG configured in tests

    event = audit.log(AuditAction.LOGIN, actor="alice", tenant_id="t1", detail="d")
    # P1 #11: event_id is UUID-based, not predictable timestamp+seq
    assert event.event_id.startswith("aud_")
    assert len(event.event_id) > len("aud_") + 16

    rows = audit._sqlite.query_events(actor="alice")
    assert len(rows) == 1
    assert rows[0]["action"] == "login"
    assert rows[0]["tenant_id"] == "t1"

    summary = audit.summary(tenant_id="t1")
    assert summary["total_events"] == 1


def test_sqlite_audit_store_roundtrip(tmp_path):
    from maop.enterprise.audit import SqliteAuditStore

    store = SqliteAuditStore(db_path=tmp_path / "audit.db")
    assert store.available
    store.save_event({
        "event_id": "aud_x1", "timestamp": time.time(), "action": "api_call",
        "severity": "info", "actor": "bob", "tenant_id": "t2",
        "resource": "agents", "detail": "", "result": "success",
        "ip_address": "", "user_agent": "", "metadata": {"k": "v"},
        "risk_level": "low", "category": "api", "tags": ["x"],
    })
    rows = store.query_events(actor="bob")
    assert len(rows) == 1
    assert json.loads(rows[0]["metadata"]) == {"k": "v"}


# ── #12: RBAC SQLite fallback ───────────────────────────────────────


def test_rbac_sqlite_persistence_across_instances(tmp_path, enterprise_edition):
    from maop.enterprise.rbac import RBACManager, Role, SqliteRBACStore

    store = SqliteRBACStore(db_path=tmp_path / "rbac.db")
    m1 = RBACManager(sqlite_store=store)
    m1.grant_role("user1", Role.ADMIN, granted_by="root", tenant_id="t1")

    # a new manager sharing the same store sees the grant (restart-safe)
    m2 = RBACManager(sqlite_store=store)
    assert Role.ADMIN in m2.user_roles("user1", tenant_id="t1")


def test_rbac_grant_dedup(tmp_path, enterprise_edition):
    from maop.enterprise.rbac import RBACManager, Role, SqliteRBACStore

    store = SqliteRBACStore(db_path=tmp_path / "rbac.db")
    mgr = RBACManager(sqlite_store=store)
    mgr.grant_role("user1", Role.OPERATOR)
    mgr.grant_role("user1", Role.OPERATOR)  # duplicate grant
    assert mgr.user_roles("user1").count(Role.OPERATOR) == 1


def test_rbac_memory_only_when_fallback_disabled(enterprise_edition):
    from maop.enterprise.rbac import RBACManager

    mgr = RBACManager(enable_sqlite_fallback=False)
    assert mgr._sqlite is None
    assert mgr._pg is None


# ── #14/#15: license manager soft delete + verification-only mode ───


@pytest.fixture
def signing_manager(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from maop.enterprise.license_manager import LicenseManager

    priv = Ed25519PrivateKey.generate()
    key_path = tmp_path / "priv.pem"
    key_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return LicenseManager(
        private_key_path=key_path, db_path=tmp_path / "licenses.db"
    )


def test_delete_license_is_soft_and_keeps_audit(signing_manager):
    rec = signing_manager.create_license(
        customer="acme", expires_at="2027-01-01T00:00:00Z"
    )
    assert signing_manager.delete_license(rec.license_id, actor="admin") is True

    # default listing excludes soft-deleted licenses
    assert all(
        r.license_id != rec.license_id for r in signing_manager.list_licenses()
    )
    # explicit status='deleted' surfaces the record
    deleted = signing_manager.list_licenses(status="deleted")
    match = [r for r in deleted if r.license_id == rec.license_id]
    assert len(match) == 1
    assert match[0].status == "deleted"
    assert match[0].deleted_at

    # P1 #14: audit trail survives deletion (compliance evidence)
    logs = signing_manager.get_audit_logs(license_id=rec.license_id)
    assert len(logs) >= 2  # at least create + delete events


def test_verification_only_mode_refuses_signing(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from maop.enterprise.license_manager import (
        LicenseManager,
        LicenseValidationError,
    )

    priv = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    mgr = LicenseManager(public_key_path=pub_path, db_path=tmp_path / "lic.db")
    # P1 #15: no private key → signing fails loudly (no ephemeral fallback)
    with pytest.raises(LicenseValidationError):
        mgr.create_license(customer="acme", expires_at="2027-01-01T00:00:00Z")


# ── P0 #8: fingerprint / max_users / features enforcement ───────────


@pytest.fixture
def ephemeral_validator(tmp_path):
    """LicenseValidator with an ephemeral keypair + a key factory."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from maop.enterprise.license import LicenseValidator

    priv = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    validator = LicenseValidator(public_key_path=pub_path)

    def make_key(**extra) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "customer": "acme",
            "edition": "enterprise",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=365)).isoformat(),
            **extra,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = priv.sign(payload_bytes)
        return (
            "MAOP-ENT-"
            + base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
            + "."
            + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        )

    return validator, make_key


def test_fingerprint_match_passes(ephemeral_validator):
    validator, make_key = ephemeral_validator
    fp = "a" * 64
    info = validator.validate(make_key(fingerprint=fp), expected_fingerprint=fp)
    assert info.fingerprint == fp


def test_fingerprint_mismatch_rejected(ephemeral_validator):
    from maop.enterprise.license import LicenseFingerprintError

    validator, make_key = ephemeral_validator
    key = make_key(fingerprint="a" * 64)
    with pytest.raises(LicenseFingerprintError):
        validator.validate(key, expected_fingerprint="b" * 64)


def test_license_without_fingerprint_skips_check(ephemeral_validator):
    validator, make_key = ephemeral_validator
    # legacy license (no fingerprint field) is not machine-bound
    info = validator.validate(make_key(), expected_fingerprint="anything")
    assert info.fingerprint is None


def test_enforce_max_users():
    from maop.enterprise.license import (
        LicenseInfo,
        LicenseLimitError,
        enforce_max_users,
    )

    now = datetime.now(timezone.utc)
    info = LicenseInfo(
        customer="acme", edition="enterprise",
        issued_at=now, expires_at=now + timedelta(days=1), max_users=5,
    )
    enforce_max_users(info, 5)  # at the limit → allowed
    with pytest.raises(LicenseLimitError):
        enforce_max_users(info, 6)
    info.max_users = None  # unlimited
    enforce_max_users(info, 10_000)


def test_feature_allowed():
    from maop.enterprise.license import LicenseInfo, feature_allowed

    now = datetime.now(timezone.utc)
    base = {
        "customer": "acme", "edition": "enterprise",
        "issued_at": now, "expires_at": now + timedelta(days=1),
    }
    assert feature_allowed(LicenseInfo(**base), "sso") is True  # None = all
    scoped = LicenseInfo(**base, features=["sso", "audit"])
    assert feature_allowed(scoped, "sso") is True
    assert feature_allowed(scoped, "ha") is False


# ── #17: CRL license_id matching + signature verification ───────────


def _write_crl_cache(path: Path, entries: list[dict]) -> None:
    path.write_text(
        json.dumps({"revoked": entries, "updated_at": "2026-08-28T00:00:00Z"}),
        encoding="utf-8",
    )


def _crl_checker(tmp_path, entries):
    from maop.enterprise.crl import CRLChecker

    cache = tmp_path / "crl.json"
    _write_crl_cache(cache, entries)
    return CRLChecker(crl_url="", cache_path=cache, cache_ttl_s=3600)


def test_crl_license_id_exact_match(tmp_path):
    checker = _crl_checker(tmp_path, [
        {"license_id": "lic-1", "customer": "acme",
         "reason": "abuse", "revoked_at": "2026-01-01"},
    ])
    revoked, reason = checker.is_revoked("acme", license_id="lic-1")
    assert revoked is True
    assert reason == "abuse"


def test_crl_license_id_mismatch_no_customer_fallback(tmp_path):
    # Both the entry and the query carry license_id but they differ →
    # MUST NOT fall back to customer matching (a re-issued license for
    # the same customer is not revoked).
    checker = _crl_checker(tmp_path, [
        {"license_id": "lic-1", "customer": "acme",
         "reason": "abuse", "revoked_at": "2026-01-01"},
    ])
    revoked, _ = checker.is_revoked("acme", license_id="lic-OTHER")
    assert revoked is False


def test_crl_customer_fallback_when_entry_has_no_license_id(tmp_path):
    checker = _crl_checker(tmp_path, [
        {"customer": "old-co", "reason": "r", "revoked_at": "2026-01-01"},
    ])
    revoked, _ = checker.is_revoked("old-co", license_id="any-lic")
    assert revoked is True
    revoked, _ = checker.is_revoked("someone-else", license_id="any-lic")
    assert revoked is False


def test_crl_signature_verification_states(tmp_path):
    from cryptography.hazmat.primitives import serialization

    from maop.enterprise.crl import CRLChecker

    test_key = REPO_ROOT / "scripts" / "test_signing_key.pem"
    bundled_pub = REPO_ROOT / "maop" / "enterprise" / "keys" / "public_key.pem"
    if not test_key.exists() or not bundled_pub.exists():
        pytest.skip("test signing keypair not present locally")

    priv = serialization.load_pem_private_key(test_key.read_bytes(), password=None)
    pub = serialization.load_pem_public_key(bundled_pub.read_bytes())
    probe = b"pairing-probe"
    try:
        pub.verify(priv.sign(probe), probe)
    except Exception:
        pytest.skip("test signing key does not match bundled public key")

    data = {
        "revoked": [{"license_id": "lic-9", "customer": "acme",
                     "reason": "x", "revoked_at": "2026-01-01"}],
        "updated_at": "2026-08-28",
    }
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    sig = base64.urlsafe_b64encode(priv.sign(payload)).rstrip(b"=").decode()

    assert CRLChecker._verify_crl_signature({**data, "signature": sig}) is True
    assert CRLChecker._verify_crl_signature({**data, "signature": "AAAA"}) is False
    assert CRLChecker._verify_crl_signature(data) is None  # unsigned → warn


# ── #19: sso_store encrypts secrets at rest ─────────────────────────


def test_sso_store_encrypts_secrets_at_rest(tmp_path, monkeypatch, enterprise_edition):
    from cryptography.fernet import Fernet

    monkeypatch.setenv("MAOP_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("MAOP_KEY_FILE", raising=False)

    from maop.enterprise.sso_store import SSOProviderCreate, SSOProviderStore

    store = SSOProviderStore(db_path=tmp_path / "sso_providers.db")
    created = store.create(SSOProviderCreate(
        name="test-oidc",
        protocol="oidc",
        config={
            "client_id": "cid",
            "client_secret": "super-secret-value",
            "authorize_url": "https://idp/authorize",
            "token_url": "https://idp/token",
        },
    ))

    # read back through the store → transparently decrypted
    fetched = store.get(created.id)
    assert fetched is not None
    assert fetched.config["client_secret"] == "super-secret-value"

    # raw DB row must NOT contain the plaintext secret
    conn = sqlite3.connect(str(store._db_path))
    try:
        raw = conn.execute(
            "SELECT config FROM sso_providers WHERE id=?", (created.id,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert "super-secret-value" not in raw


# ── #20: quota atomic consume + negative clamp ──────────────────────


def test_quota_consume_enforces_hard_limit_atomically(tmp_path, enterprise_edition):
    from maop.enterprise.quota import QuotaManager

    qm = QuotaManager(tmp_path / "quota.db")
    qm.set_quota("t1", "api_calls", hard_limit=2)
    assert qm.consume("t1", "api_calls").allowed is True
    assert qm.consume("t1", "api_calls").allowed is True
    third = qm.consume("t1", "api_calls")
    assert third.allowed is False
    assert third.reason  # human-readable rejection reason


def test_quota_consume_negative_amount_rejected(tmp_path, enterprise_edition):
    from maop.enterprise.quota import QuotaManager

    qm = QuotaManager(tmp_path / "quota.db")
    result = qm.consume("t1", "api_calls", amount=-1)
    assert result.allowed is False


def test_quota_update_usage_clamps_at_zero(tmp_path, enterprise_edition):
    from maop.enterprise.quota import QuotaManager

    qm = QuotaManager(tmp_path / "quota.db")
    qm.set_quota("t1", "concurrent_tasks", hard_limit=10)
    assert qm.update_usage("t1", "concurrent_tasks", 3) == 3
    # releasing more than in use must clamp to 0, never go negative
    assert qm.update_usage("t1", "concurrent_tasks", -100) == 0
    # fresh row with a negative delta inserts as 0 (no negative usage)
    assert qm.update_usage("t2", "concurrent_tasks", -5) == 0


def test_quota_consume_without_quota_is_fail_open(tmp_path, enterprise_edition):
    from maop.enterprise.quota import QuotaManager

    qm = QuotaManager(tmp_path / "quota.db")
    # no set_quota → unlimited, allowed
    assert qm.consume("t1", "api_calls").allowed is True


# ── #22: notification stats return int counts ───────────────────────


def test_notification_stats_returns_int_counts(tmp_path):
    from maop.enterprise.notification.event_bus import EventBus
    from maop.enterprise.notification.manager import NotificationManager
    from maop.enterprise.notification.store import NotificationStore

    store = NotificationStore(db_path=tmp_path / "notif.db")
    mgr = NotificationManager(store=store, event_bus=EventBus())
    stats = mgr.stats()
    statuses = stats["statuses"]
    assert set(statuses) == {"sent", "pending", "retrying", "dead_letter"}
    # P1 #22: values must be int totals, not row lists
    assert all(isinstance(v, int) for v in statuses.values())
    assert statuses["sent"] == 0


# ── #23: tenant update whitelist ────────────────────────────────────


def test_update_tenant_whitelist_blocks_identity_fields(enterprise_edition):
    from maop.enterprise.tenant import TenantManager

    tm = TenantManager()
    tenant = tm.create_tenant("t1", "Acme")
    original_created_at = tenant.created_at

    updated = tm.update_tenant(
        "t1",
        name="Acme Corp",       # whitelisted
        plan="pro",             # whitelisted
        created_at=0.0,         # NOT whitelisted → ignored
        some_unknown_field="x",  # NOT whitelisted → ignored
    )
    assert updated.name == "Acme Corp"
    assert updated.plan == "pro"
    assert updated.created_at == original_created_at  # untouched
    assert updated.updated_at > 0  # set by update_tenant itself
    assert updated.tenant_id == "t1"  # identity field never overwritable


# ── #21: n8n webhook endpoint ───────────────────────────────────────


def test_n8n_trigger_posts_to_webhook_endpoint(enterprise_edition, monkeypatch):
    import httpx

    from maop.enterprise.n8n import N8nClient

    captured: dict = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers

        class _Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"executionId": "exec-1", "status": "success"}

        return _Resp()

    monkeypatch.setattr(httpx, "post", fake_post)
    client = N8nClient(base_url="http://n8n.local:5678", api_key="k")
    result = client.trigger_workflow("wf-123", data={"a": 1})

    # P1 #21: /webhook/{path}, NOT the nonexistent /api/v1/.../execute
    assert captured["url"] == "http://n8n.local:5678/webhook/wf-123"
    assert captured["json"] == {"a": 1}
    assert result.execution_id == "exec-1"
    assert result.status == "success"

    # custom webhook path + editor test mode
    client.trigger_workflow("wf-123", webhook_path="my-hook", use_test_webhook=True)
    assert captured["url"] == "http://n8n.local:5678/webhook-test/my-hook"


# ── #24: HA node registration auth hook ─────────────────────────────


def test_ha_node_auth_rejects_registration(enterprise_edition):
    from maop.enterprise.ha import HAManager

    ha = HAManager()
    ha.set_node_authenticator(lambda node_id, address: False)
    with pytest.raises(PermissionError):
        ha.register_node("n1", "10.0.0.1:8000")


def test_ha_node_auth_exception_fails_closed(enterprise_edition):
    from maop.enterprise.ha import HAManager

    def boom(node_id, address):
        raise RuntimeError("auth backend down")

    ha = HAManager()
    ha.set_node_authenticator(boom)
    with pytest.raises(PermissionError):
        ha.register_node("n1", "10.0.0.1:8000")


def test_ha_node_auth_allows_and_default_open(enterprise_edition):
    from maop.enterprise.ha import HAManager

    ha = HAManager()
    ha.set_node_authenticator(lambda node_id, address: True)
    assert ha.register_node("n1", "10.0.0.1:8000").node_id == "n1"

    ha2 = HAManager()  # no authenticator → backward-compatible open
    assert ha2.register_node("n2", "10.0.0.2:8000").node_id == "n2"


# ── #25: TLS cert/key pair match ────────────────────────────────────


def test_cert_key_pair_match_detection(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from maop.enterprise.tls_auto import _cert_key_pair_matches

    def gen_pair():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls-test")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        return key, cert

    key, cert = gen_pair()
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    assert _cert_key_pair_matches(str(cert_path), str(key_path)) is True

    # a different private key must NOT match
    other_key, _ = gen_pair()
    other_key_path = tmp_path / "other_key.pem"
    other_key_path.write_bytes(other_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    assert _cert_key_pair_matches(str(cert_path), str(other_key_path)) is False

    # missing files → fail-closed False
    assert _cert_key_pair_matches(str(tmp_path / "missing.pem"), str(key_path)) is False


# ── #13: SSO session + PKCE state persistence ───────────────────────


def test_sso_session_store_roundtrip(tmp_path, enterprise_edition):
    from maop.enterprise.sso import (
        SSOConfig,
        SSOManager,
        SSOSession,
        SSOUser,
    )
    from maop.enterprise.sso_session_store import SqliteSSOStore

    store = SqliteSSOStore(db_path=tmp_path / "sso.db")
    assert store.available
    mgr = SSOManager(config=SSOConfig(), session_store=store)

    now = time.time()
    session = SSOSession(
        session_id="sess_1",
        user=SSOUser(external_id="oidc:u1"),
        expires_at=now + 3600,
        created_at=now,
    )
    mgr._sessions["sess_1"] = session
    mgr._persist_session(session)

    # simulate process restart: fresh manager, same store, empty memory
    mgr2 = SSOManager(config=SSOConfig(), session_store=store)
    recovered = mgr2.validate_session("sess_1")
    assert recovered is not None
    assert recovered.user.external_id == "oidc:u1"

    # logout clears the persisted session too
    assert mgr2.logout("sess_1") is True
    assert store.get_session_json("sess_1") is None


def test_maybe_open_store_env_semantics(tmp_path, monkeypatch):
    from maop.enterprise.sso_session_store import maybe_open_store

    monkeypatch.delenv("MAOP_SSO_SESSION_PERSIST", raising=False)
    assert maybe_open_store() is None
    monkeypatch.setenv("MAOP_SSO_SESSION_PERSIST", "0")
    assert maybe_open_store() is None

    explicit = tmp_path / "explicit.db"
    store = maybe_open_store(str(explicit))
    assert store is not None
    assert Path(store.db_path) == explicit

    monkeypatch.setenv("MAOP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MAOP_SSO_SESSION_PERSIST", "1")
    store2 = maybe_open_store()
    assert store2 is not None
    assert Path(store2.db_path) == tmp_path / "sso_sessions.db"


def test_registry_pending_state_survives_restart(tmp_path, enterprise_edition):
    from maop.enterprise.sso_registry import SSOProviderRegistry
    from maop.enterprise.sso_session_store import SqliteSSOStore
    from maop.enterprise.sso_store import SSOProviderResponse

    class _FakeStore:
        def __init__(self, resp):
            self._resp = resp

        def get(self, provider_id):
            return self._resp if provider_id == self._resp.id else None

    resp = SSOProviderResponse(
        id=1, name="test-idp", protocol="oidc", enabled=True,
        config={
            "client_id": "cid", "client_secret": "sec",
            "authorize_url": "https://idp.example.com/authorize",
            "token_url": "",
            "redirect_uri": "https://app.example.com/cb",
        },
    )
    pending_store = SqliteSSOStore(db_path=tmp_path / "sso.db")
    registry = SSOProviderRegistry(store=_FakeStore(resp), pending_store=pending_store)
    _, state = registry.prepare_oidc_authorize(1)

    # simulate restart: in-memory pending cleared
    registry._pending.clear()
    # state recovered from the persistent store → CSRF check passes,
    # then fails at token exchange (token_url empty)
    with pytest.raises(ValueError, match="token_url"):
        registry.handle_oidc_callback(1, code="c", state=state)
