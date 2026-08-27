"""MAOP Enterprise SSO Provider Registry — 多 IdP 管理中心。

PRD 3.5.1：从 ``sso_providers`` 表加载多个 IdP 配置，每个 IdP 对应一个
:class:`SSOManager` 实例。提供按 provider_id 获取 manager、构造 authorize
URL（含 PKCE）、处理 callback、生成 SAML SP Metadata、测试连接等能力。

设计：
  - 懒加载 + 缓存：首次访问某 provider_id 时从 :class:`SSOProviderStore`
    读取配置并实例化 :class:`SSOManager`，缓存到内存。
  - 失效：CRUD 操作后调用 :meth:`invalidate` 清除缓存。
  - PKCE state 暂存：每次 OIDC authorize 生成 (state, code_verifier) 并
    存入 ``_pending`` 字典；callback 时按 state 取出 code_verifier 并校验
    （PRD NFR-S04 防 CSRF）。
"""

from __future__ import annotations

import logging
import secrets
import time
import urllib.error
import urllib.request
from typing import Any

from maop.config.edition import FeatureFlag, require_feature
from maop.enterprise.sso import (
    SSOConfig,
    SSOManager,
    SSOProvider,
    SSOSession,
    generate_pkce_pair,
)
from maop.enterprise.sso_store import (
    SSOProviderResponse,
    SSOProviderStore,
    mask_sensitive_fields,
)

logger = logging.getLogger(__name__)


# ── SAML SP Metadata 生成（PRD 4.2.4） ──────────────────────────────
_SAML_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


def generate_sp_metadata(
    sp_entity_id: str,
    acs_url: str,
    *,
    want_signed: bool = True,
) -> str:
    """生成 SAML SP Metadata XML（PRD 4.2.4）。

    Args:
        sp_entity_id: SP Entity ID。
        acs_url: AssertionConsumerService URL。
        want_signed: 是否要求签名 Response（``WantSigned="true"``）。

    Returns:
        XML 字符串（UTF-8）。
    """
    # 转义 XML 特殊字符
    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="{_SAML_MD_NS}" entityID="{esc(sp_entity_id)}">'
        f'<SPSSODescriptor protocolSupportEnumeration="{_SAMLP_NS}" '
        f'WantAssertionsSigned="{"true" if want_signed else "false"}">'
        f'<AssertionConsumerService index="0" '
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{esc(acs_url)}" />'
        f'</SPSSODescriptor>'
        f'</EntityDescriptor>'
    )


# ── SSOProviderRegistry ─────────────────────────────────────────────
class SSOProviderRegistry:
    """多 IdP 注册中心（PRD 3.5.1）。

    从 :class:`SSOProviderStore` 加载 IdP 配置，为每个 IdP 实例化一个
    :class:`SSOManager`，并提供 PKCE state 暂存、连接测试等能力。
    """

    def __init__(
        self,
        store: SSOProviderStore | None = None,
        pending_store: Any = None,
    ) -> None:
        require_feature(FeatureFlag.SSO)
        self._store = store or SSOProviderStore()
        # provider_id → SSOManager 缓存
        self._managers: dict[int, SSOManager] = {}
        # provider_id → SSOProviderResponse 缓存（含解密后的 config）
        self._configs: dict[int, SSOProviderResponse] = {}
        # PKCE + state 暂存：state → (provider_id, code_verifier, created_at)
        self._pending: dict[str, tuple[int, str, float]] = {}
        # state TTL（秒）
        self._state_ttl = 600.0
        # P1 #13: 可选 SQLite 持久化（显式传入或 MAOP_SSO_SESSION_PERSIST 启用），
        # 解决进程重启后 OIDC 回调 state mismatch 问题
        if pending_store is None:
            from maop.enterprise.sso_session_store import maybe_open_store
            pending_store = maybe_open_store()
        self._pending_store = pending_store

    @property
    def store(self) -> SSOProviderStore:
        return self._store

    # ── 缓存管理 ───────────────────────────────────────────────────
    def invalidate(self, provider_id: int | None = None) -> None:
        """失效缓存。``provider_id=None`` 清空所有缓存。"""
        if provider_id is None:
            self._managers.clear()
            self._configs.clear()
        else:
            self._managers.pop(provider_id, None)
            self._configs.pop(provider_id, None)

    def _load(self, provider_id: int) -> SSOProviderResponse | None:
        """加载并缓存 IdP 配置。返回 None 若不存在。"""
        if provider_id in self._configs:
            return self._configs[provider_id]
        resp = self._store.get(provider_id)
        if resp is None:
            return None
        self._configs[provider_id] = resp
        return resp

    def _get_manager(self, provider_id: int) -> SSOManager | None:
        """获取指定 IdP 的 SSOManager（懒加载 + 缓存）。"""
        if provider_id in self._managers:
            return self._managers[provider_id]
        resp = self._load(provider_id)
        if resp is None:
            return None
        cfg = self._build_sso_config(resp)
        mgr = SSOManager(config=cfg)
        self._managers[provider_id] = mgr
        return mgr

    @staticmethod
    def _build_sso_config(resp: SSOProviderResponse) -> SSOConfig:
        """从 SSOProviderResponse 构造 SSOConfig。"""
        c = resp.config
        if resp.protocol == "oidc":
            return SSOConfig(
                provider=SSOProvider.OIDC,
                client_id=str(c.get("client_id", "")),
                client_secret=str(c.get("client_secret", "")),
                issuer_url=str(c.get("issuer_url", "")),
                authorize_url=str(c.get("authorize_url", "")),
                token_url=str(c.get("token_url", "")),
                userinfo_url=str(c.get("userinfo_url", "")),
                redirect_uri=str(c.get("redirect_uri", "")),
                scopes=list(c.get("scopes", ["openid", "profile", "email"])),
                use_pkce=bool(c.get("use_pkce", True)),
                attribute_mapping=resp.attribute_mapping,
                role_mapping=resp.attribute_mapping.get("role_mapping", {}),
            )
        # saml
        return SSOConfig(
            provider=SSOProvider.SAML,
            saml_entity_id=str(c.get("sp_entity_id", c.get("entity_id", "maop-sp"))),
            saml_acs_url=str(c.get("acs_url", c.get("redirect_uri", ""))),
            saml_idp_cert=str(c.get("x509_cert", "")),
            saml_sso_url=str(c.get("sso_url", "")),
            saml_slo_url=str(c.get("slo_url", "")),
            saml_metadata_url=str(c.get("metadata_url", "")),
            redirect_uri=str(c.get("acs_url", c.get("redirect_uri", ""))),
            attribute_mapping=resp.attribute_mapping,
            role_mapping=resp.attribute_mapping.get("role_mapping", {}),
        )

    # ── OIDC 登录跳转 ─────────────────────────────────────────────
    def prepare_oidc_authorize(
        self,
        provider_id: int,
        *,
        state: str = "",
    ) -> tuple[str, str]:
        """构造 OIDC authorize URL + 暂存 (state, code_verifier)。

        Returns:
            (authorize_url, state) — 前端 302 跳转到 authorize_url。
            state 同时写入 ``_pending``，callback 时按 state 取出 code_verifier。

        Raises:
            KeyError: provider_id 不存在或未启用。
            ValueError: IdP 协议非 oidc。
        """
        resp = self._load(provider_id)
        if resp is None or not resp.enabled:
            raise KeyError(f"SSO provider id={provider_id} not found or disabled")
        if resp.protocol != "oidc":
            raise ValueError(f"Provider id={provider_id} is not OIDC")

        mgr = self._get_manager(provider_id)
        assert mgr is not None
        if not state:
            state = secrets.token_urlsafe(24)

        code_verifier = ""
        code_challenge = ""
        if mgr.config.use_pkce:
            code_verifier, code_challenge = generate_pkce_pair()

        url = mgr.get_authorize_url(state=state, code_challenge=code_challenge)
        self._pending[state] = (provider_id, code_verifier, time.time())
        # P1 #13: 持久化 state（重启后回调仍可匹配）
        if self._pending_store is not None:
            try:
                self._pending_store.save_pending(
                    state, provider_id, code_verifier, time.time()
                )
            except Exception as exc:
                logger.warning("[sso_registry] pending persist failed: %s", exc)
        self._gc_pending()
        return url, state

    def handle_oidc_callback(
        self,
        provider_id: int,
        code: str,
        state: str = "",
    ) -> SSOSession:
        """处理 OIDC callback。

        校验 state（PRD NFR-S04 防 CSRF），取出 code_verifier（PKCE），
        调用 :meth:`SSOManager.handle_callback`。

        Raises:
            ValueError: state 缺失 / 不匹配 / 已过期 / code 为空。
            KeyError: provider_id 不存在。
        """
        if not code:
            raise ValueError("Missing authorization code")
        # P0 fix: state 为必填（fail-closed 防 CSRF）——空 state 直接拒绝，
        # 不再跳过校验（旧实现 `if state:` 允许无 state 回调绕过 CSRF 防护）
        if not state:
            raise ValueError("Missing state parameter (required for CSRF protection)")
        code_verifier = ""
        pending = self._pending.pop(state, None)
        if pending is None and self._pending_store is not None:
            # P1 #13: 内存未命中（如进程重启后）→ 尝试持久化后端
            try:
                pending = self._pending_store.pop_pending(state)
            except Exception as exc:
                logger.warning("[sso_registry] pending store lookup failed: %s", exc)
        if pending is None:
            raise ValueError(f"SSO state mismatch or expired: {state!r}")
        pid, code_verifier, _ = pending
        if pid != provider_id:
            raise ValueError(
                f"SSO state provider mismatch: expected {pid}, got {provider_id}"
            )
        mgr = self._get_manager(provider_id)
        if mgr is None:
            raise KeyError(f"SSO provider id={provider_id} not found")
        return mgr.handle_callback(code, state=state, code_verifier=code_verifier)

    # ── SAML 登录跳转 ─────────────────────────────────────────────
    def prepare_saml_authorize(
        self,
        provider_id: int,
        *,
        relay_state: str = "",
    ) -> tuple[str, str]:
        """构造 SAML AuthnRequest 跳转 URL + RelayState。

        Returns:
            (sso_url, relay_state) — 前端 302 跳转到 sso_url。
        """
        resp = self._load(provider_id)
        if resp is None or not resp.enabled:
            raise KeyError(f"SSO provider id={provider_id} not found or disabled")
        if resp.protocol != "saml":
            raise ValueError(f"Provider id={provider_id} is not SAML")

        mgr = self._get_manager(provider_id)
        assert mgr is not None
        if not relay_state:
            relay_state = secrets.token_urlsafe(24)
        url = mgr.get_authorize_url(state=relay_state)
        return url, relay_state

    def handle_saml_acs(
        self,
        provider_id: int,
        saml_response_b64: str,
        relay_state: str = "",
    ) -> SSOSession:
        """处理 SAML ACS（Assertion Consumer Service）。

        委托给 :meth:`SSOManager.handle_callback`（内部转 SAMLHandler）。
        """
        mgr = self._get_manager(provider_id)
        if mgr is None:
            raise KeyError(f"SSO provider id={provider_id} not found")
        return mgr.handle_callback(saml_response_b64, state=relay_state)

    # ── SAML SP Metadata ──────────────────────────────────────────
    def get_sp_metadata(self, provider_id: int) -> str:
        """生成 SAML SP Metadata XML（PRD 4.2.4）。

        Raises:
            KeyError: provider_id 不存在。
            ValueError: IdP 协议非 saml。
        """
        resp = self._load(provider_id)
        if resp is None:
            raise KeyError(f"SSO provider id={provider_id} not found")
        if resp.protocol != "saml":
            raise ValueError(f"Provider id={provider_id} is not SAML")
        c = resp.config
        sp_entity_id = str(c.get("sp_entity_id", "maop-sp"))
        acs_url = str(c.get("acs_url", "")).replace("{provider_id}", str(provider_id))
        want_signed = bool(c.get("want_signed", True))
        return generate_sp_metadata(sp_entity_id, acs_url, want_signed=want_signed)

    # ── 测试连接（PRD 4.2.3） ─────────────────────────────────────
    def test_connection(self, provider_id: int) -> dict[str, Any]:
        """测试 IdP 连接（PRD 4.2.3）。

        对 OIDC：HEAD/GET authorize_url + token_url，记录可达性 + 延迟。
        对 SAML：GET sso_url，记录可达性 + 延迟。

        Returns:
            ``{"reachable": bool, "protocol": str, "details": {...}}``
            失败时附加 ``"error": str``。
        """
        resp = self._load(provider_id)
        if resp is None:
            raise KeyError(f"SSO provider id={provider_id} not found")

        if resp.protocol == "oidc":
            return self._test_oidc(resp)
        return self._test_saml(resp)

    @staticmethod
    def _probe_url(url: str, timeout: float = 10.0) -> tuple[bool, float, str]:
        """探测 URL 可达性。返回 (reachable, latency_ms, error_msg)。"""
        if not url:
            return False, 0.0, "URL is empty"
        t0 = time.time()
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "MAOP-SSO-Test/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                _ = r.status
            return True, (time.time() - t0) * 1000.0, ""
        except urllib.error.HTTPError as exc:
            # HTTP 4xx/5xx 仍算"可达"（端点存在但拒绝），但记录错误
            latency = (time.time() - t0) * 1000.0
            if exc.code in (404,):
                return False, latency, f"HTTP {exc.code}"
            return True, latency, f"HTTP {exc.code}"
        except urllib.error.URLError as exc:
            return False, (time.time() - t0) * 1000.0, f"unreachable: {exc.reason}"
        except Exception as exc:  # pragma: no cover — 防御性
            return False, (time.time() - t0) * 1000.0, f"error: {exc}"

    def _test_oidc(self, resp: SSOProviderResponse) -> dict[str, Any]:
        c = resp.config
        authorize_url = str(c.get("authorize_url", ""))
        token_url = str(c.get("token_url", ""))
        userinfo_url = str(c.get("userinfo_url", ""))

        ok_auth, lat_auth, err_auth = self._probe_url(authorize_url)
        ok_tok, lat_tok, err_tok = self._probe_url(token_url)
        ok_user, _lat_user, _err_user = (
            self._probe_url(userinfo_url) if userinfo_url else (True, 0.0, "")
        )

        reachable = ok_auth and ok_tok
        details: dict[str, Any] = {
            "authorize_url_resolved": ok_auth,
            "token_url_resolved": ok_tok,
            "userinfo_url_resolved": ok_user if bool(userinfo_url) else None,
            "discovery_fetched": False,
            "latency_ms": round(max(lat_auth, lat_tok), 1),
        }
        result: dict[str, Any] = {
            "reachable": reachable,
            "protocol": "oidc",
            "details": details,
        }
        if not reachable:
            errors = [e for e in (err_auth, err_tok) if e]
            result["error"] = "; ".join(errors) or "OIDC endpoints unreachable"
        return result

    def _test_saml(self, resp: SSOProviderResponse) -> dict[str, Any]:
        c = resp.config
        sso_url = str(c.get("sso_url", ""))
        ok, lat, err = self._probe_url(sso_url)
        details: dict[str, Any] = {
            "sso_url_resolved": ok,
            "latency_ms": round(lat, 1),
        }
        result: dict[str, Any] = {
            "reachable": ok,
            "protocol": "saml",
            "details": details,
        }
        if not ok:
            result["error"] = err or "SAML SSO URL unreachable"
        return result

    # ── 登录页：列出已启用 IdP（PRD 4.2.5） ───────────────────────
    def list_enabled_for_login(self) -> dict[str, Any]:
        """列出已启用 IdP（公开端点，不返回敏感配置）。

        Returns:
            ``{"providers": [...], "count": N, "auto_redirect_provider_id": int|None}``
        """
        enabled = self._store.list_enabled()
        providers = [
            {
                "id": p.id,
                "name": p.name,
                "protocol": p.protocol,
                "auto_redirect": p.auto_redirect,
            }
            for p in enabled
        ]
        auto_redirect_id: int | None = None
        if len(enabled) == 1 and enabled[0].auto_redirect:
            auto_redirect_id = enabled[0].id
        return {
            "providers": providers,
            "count": len(providers),
            "auto_redirect_provider_id": auto_redirect_id,
        }

    # ── 脱敏响应 helper ──────────────────────────────────────────
    @staticmethod
    def to_masked_response(resp: SSOProviderResponse) -> dict[str, Any]:
        """转换为脱敏的 dict（用于 API 响应）。"""
        d = resp.model_dump()
        d["config"] = mask_sensitive_fields(d["config"])
        return d  # type: ignore

    # ── state GC ─────────────────────────────────────────────────
    def _gc_pending(self) -> None:
        """清理过期 state（超过 ``_state_ttl`` 秒）。"""
        now = time.time()
        expired = [s for s, (_, _, t) in self._pending.items() if now - t > self._state_ttl]
        for s in expired:
            self._pending.pop(s, None)
        if self._pending_store is not None:
            try:
                self._pending_store.gc_pending(self._state_ttl)
            except Exception as exc:
                logger.warning("[sso_registry] pending store GC failed: %s", exc)


__all__ = [
    "SSOProviderRegistry",
    "generate_sp_metadata",
]