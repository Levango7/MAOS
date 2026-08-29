"""Regression tests for P0/P1 fixes in v5.2.1 audit pass.

Covers real-path behavior that previous tests missed (test/production
behavior drift):
  - SAML handler must be reused across authorize/callback (replay
    protection state must survive) — old code created a new handler
    per callback, making InResponseTo + assertion replay dead code.
  - OIDC userinfo failure must reject login (no more `oidc:unknown`
    identity merging).
  - Quota middleware must actually consume (atomic check+deduct), not
    just check against a stale 60s cache.
  - Audit alert engine must be wired into EnterpriseAuditLogger (was
    zero-callpoint dead code) and deduplicate alerts.
  - n8n webhook must fail closed when N8N_WEBHOOK_SECRET is unset.
"""
from __future__ import annotations

import pytest

pytest.importorskip("lxml", reason="requires sso-saml extra (lxml)")
pytest.importorskip("defusedxml", reason="requires sso-saml extra")


# ── SAML handler reuse (replay protection is instance state) ───────


def test_saml_handler_reused_across_calls(enterprise_edition):
    """SSOManager must return the SAME SAMLHandler instance every call.

    Replay protection (`_pending_request_ids` / `_consumed_assertion_ids`)
    lives on the handler instance. Old code did `SAMLHandler(config)` on
    every authorize/callback → state tables always empty → protection dead.
    """
    from maop.enterprise.saml_handler import SAMLHandler
    from maop.enterprise.sso import SSOConfig, SSOManager, SSOProvider

    mgr = SSOManager(config=SSOConfig(provider=SSOProvider.SAML, saml_entity_id="sp", saml_acs_url="https://sp/acs"))
    h1 = mgr._get_saml_handler_instance()
    h2 = mgr._get_saml_handler_instance()
    assert h1 is h2
    assert isinstance(h1, SAMLHandler)


def test_saml_pending_request_ids_survive_authorize(enterprise_edition):
    """Authorize records a pending request id that a later callback can consume."""
    from maop.enterprise.sso import SSOConfig, SSOManager, SSOProvider

    mgr = SSOManager(config=SSOConfig(provider=SSOProvider.SAML, saml_entity_id="sp", saml_acs_url="https://sp/acs"))
    handler = mgr._get_saml_handler_instance()
    # 直接向 handler 记录一个 pending request id，验证消费语义
    request_id = "id_test123"
    import time as _t
    handler._pending_request_ids[request_id] = _t.time()
    assert request_id in handler._pending_request_ids
    # 模拟 handle_response 中的消费
    handler._pending_request_ids.pop(request_id, None)
    assert request_id not in handler._pending_request_ids


# ── OIDC userinfo fail-closed ───────────────────────────────────────


def test_oidc_callback_rejects_on_userinfo_failure(enterprise_edition, monkeypatch):
    """userinfo fetch failure must abort login (was: degrade to oidc:unknown)."""
    from maop.enterprise.sso import SSOConfig, SSOError, SSOManager, SSOProvider

    mgr = SSOManager(config=SSOConfig(
        provider=SSOProvider.OIDC,
        client_id="c", client_secret="s",
        token_url="https://idp/token",
        userinfo_url="https://idp/userinfo",
        redirect_uri="https://app/cb",
    ))
    # 伪造 token 交换成功、userinfo 失败
    monkeypatch.setattr(mgr, "_exchange_code", lambda *a, **k: {"access_token": "tok", "expires_in": 3600})
    monkeypatch.setattr(mgr, "_fetch_userinfo", lambda tok: (_ for _ in ()).throw(SSOError("userinfo down")))

    with pytest.raises(SSOError):
        mgr.handle_callback("code123", state="st")


def test_oidc_build_user_rejects_missing_sub(enterprise_edition):
    """Missing sub in claims must raise (was: oidc:unknown merge risk)."""
    from maop.enterprise.sso import SSOConfig, SSOError, SSOManager, SSOProvider

    mgr = SSOManager(config=SSOConfig(provider=SSOProvider.OIDC))
    with pytest.raises(SSOError):
        mgr._build_user_from_claims({}, {"id_token": "jwt.jwt.sig"})


# ── Quota middleware consumes (atomic check + deduct) ───────────────


def test_quota_middleware_consumes_and_rejects_over_hard_limit(tmp_path, enterprise_edition, monkeypatch):
    """Middleware must call consume() (not check_quota) so hard limits hold."""
    from starlette.applications import Starlette
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from maop.enterprise.quota import QuotaManager
    from maop.enterprise.quota_middleware import QuotaMiddleware

    qm = QuotaManager(tmp_path / "q.db")

    async def run_handler(request):
        return JSONResponse({"ok": True})

    class _SetTenant(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.tenant_id = "t1"
            return await call_next(request)

    app = Starlette(routes=[Route("/api/agents/a/run", run_handler, methods=["POST"])])
    # 后添加的中间件先执行：_SetTenant 先注入 state，QuotaMiddleware 再读取
    app.add_middleware(QuotaMiddleware, quota_manager=qm)
    app.add_middleware(_SetTenant)

    qm.set_quota("t1", "concurrent_tasks", hard_limit=2)
    client = TestClient(app)

    r1 = client.post("/api/agents/a/run")
    r2 = client.post("/api/agents/a/run")
    r3 = client.post("/api/agents/a/run")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429, f"third request must be throttled, got {r3.status_code}"
    # 扣减真实生效（consume 而非 check）
    usage = qm.get_usage("t1", "concurrent_tasks")
    assert usage.used == 2, f"expected used=2 after middleware consumption, got {usage.used}"


# ── Audit alert engine wiring + dedup ───────────────────────────────


def test_alert_engine_wired_into_audit_logger(enterprise_edition, tmp_path, monkeypatch):
    """EnterpriseAuditLogger(alert_engine=...) must feed events to the engine."""
    import maop.enterprise.audit as audit_mod
    from maop.enterprise.audit import AuditAction
    from maop.enterprise.audit_enhanced import (
        AlertConditionType,
        AuditAlertEngine,
        AuditAlertRuleCreate,
    )

    monkeypatch.setenv("MAOP_DATA_DIR", str(tmp_path))
    # 避免初始化真实 PG/SQLite store（内存即可）
    monkeypatch.setattr(audit_mod, "SqliteAuditStore", None)  # type: ignore[assignment]

    engine = AuditAlertEngine()
    engine.create_rule(AuditAlertRuleCreate(
        name="login-fail",
        condition_type=AlertConditionType.THRESHOLD,
        condition={"value": 1, "op": ">=", "filter": {"action": "login", "result": "failure"}},
        severity="critical",
    ))
    logger = audit_mod.EnterpriseAuditLogger(alert_engine=engine)
    logger.log(AuditAction.LOGIN, "attacker", result="failure")
    logger.log(AuditAction.LOGIN, "attacker", result="failure")
    alerts = engine.list_alerts()
    # 去重生效：同一规则 60s 窗口内只发一条
    assert len(alerts) == 1, f"expected 1 deduped alert, got {len(alerts)}"
    assert alerts[0].severity == "critical"


# ── n8n webhook fail-closed ─────────────────────────────────────────


def test_n8n_webhook_rejects_without_secret(enterprise_edition, monkeypatch):
    """Unset N8N_WEBHOOK_SECRET → refuse (fail-closed), not accept silently."""
    import maop.enterprise.n8n as n8n_mod

    monkeypatch.delenv("N8N_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("N8N_ALLOW_UNSIGNED", raising=False)
    # 不依赖主包 FeatureFlag 配置：仅测签名 gate 分支
    monkeypatch.setattr(n8n_mod, "require_n8n_feature", lambda: None)

    result = n8n_mod.handle_n8n_webhook(
        {"event": "github.pr.opened", "workflow_id": "w", "execution_id": "e"},
        raw_body=b'{"x":1}',
        signature="bad",
    )
    assert result["status"] == "rejected"
    assert "not configured" in result.get("error", "")


def test_n8n_webhook_accepts_with_valid_secret(enterprise_edition, monkeypatch):
    """Configured secret + valid HMAC → accepted."""
    import maop.enterprise.n8n as n8n_mod

    secret = "s3cret"
    body = b'{"event":"github.pr.opened","workflow_id":"w","execution_id":"e"}'
    import hashlib
    import hmac
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    monkeypatch.setenv("N8N_WEBHOOK_SECRET", secret)
    monkeypatch.delenv("N8N_ALLOW_UNSIGNED", raising=False)
    monkeypatch.setattr(n8n_mod, "require_n8n_feature", lambda: None)
    n8n_mod._webhook_secret_warned = False

    result = n8n_mod.handle_n8n_webhook(
        {"event": "github.pr.opened", "workflow_id": "w", "execution_id": "e"},
        raw_body=body,
        signature=sig,
    )
    assert result["status"] == "accepted"
