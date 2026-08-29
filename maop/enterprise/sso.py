"""MAOP Enterprise SSO — SAML/OIDC Single Sign-On Integration.

Provides enterprise identity provider integration:
  - OpenID Connect (via authlib) — 完整支持，含 token exchange 与 userinfo
  - SAML 2.0 — 完整支持（SP-initiated SSO + XML 签名验证），
    实现在 maop.enterprise.saml_handler.SAMLHandler（lxml + cryptography）。
  - Automatic user provisioning from IdP claims
  - Session management and token refresh
  - PKCE (Proof Key for Code Exchange) for OIDC Authorization Code Flow
  - 可配置属性映射（IdP claims → 系统用户字段/角色）
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


# ── PKCE (RFC 7636) helpers ──────────────────────────────────────────
def generate_pkce_pair() -> tuple[str, str]:
    """生成 PKCE code_verifier + code_challenge (S256)。

    Returns:
        (code_verifier, code_challenge) — verifier 为 43-128 字符的
        urlsafe-base64 字符串；challenge = BASE64URL(SHA256(verifier))。
    """
    verifier = secrets.token_urlsafe(64)  # ~85 字符，落在 43-128 范围内
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ── 默认属性映射 ─────────────────────────────────────────────────────
DEFAULT_ATTRIBUTE_MAPPING: dict[str, Any] = {
    "external_id": "sub",
    "email": "email",
    "display_name": "name",
    "roles": "groups",
    "tenant_id": "tid",
}


class SSOError(RuntimeError):
    """SSO 相关错误（如未实现的 provider、配置缺失等）。

    继承 RuntimeError 以保持与现有 handle_callback 中 RuntimeError
    抛出风格的兼容性，同时提供更精确的类型供上层 catch。
    """


class SSOProvider(str, Enum):
    SAML = "saml"
    OIDC = "oidc"


class SSOConfig(BaseModel):
    provider: SSOProvider = SSOProvider.OIDC
    client_id: str = ""
    client_secret: str = ""
    issuer_url: str = ""
    authorize_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    saml_metadata_url: str = ""
    saml_entity_id: str = ""
    saml_acs_url: str = ""  # Assertion Consumer Service URL（SP 端回调）
    saml_idp_cert: str = ""  # 直接配置 IdP X.509 证书 base64 DER（可选，优先于 metadata_url）
    saml_sso_url: str = ""  # IdP SingleSignOnService URL（直接配置，优先于 metadata 拉取）
    saml_slo_url: str = ""  # IdP SingleLogoutService URL（直接配置）
    redirect_uri: str = ""
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    auto_provision: bool = True
    default_role: str = "viewer"
    # PRD 3.5.1: PKCE 支持（OIDC Authorization Code Flow + PKCE）
    use_pkce: bool = True
    # PRD 3.4: 属性映射（IdP claims → 系统字段），空表示用默认映射
    attribute_mapping: dict[str, Any] = Field(default_factory=dict)
    # PRD 3.4: 角色映射（IdP 角色 → 系统角色），可选
    role_mapping: dict[str, str] = Field(default_factory=dict)


class SSOUser(BaseModel):
    external_id: str
    email: str = ""
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    tenant_id: str = ""
    provider: SSOProvider = SSOProvider.OIDC
    last_login: float = 0.0


class SSOSession(BaseModel):
    session_id: str
    user: SSOUser
    access_token: str = ""
    refresh_token: str = ""
    expires_at: float = 0.0
    created_at: float = 0.0


def _get_saml_handler():
    """Lazy import SAML handler to avoid lxml dependency in Personal edition.

    SAMLHandler 依赖 lxml + cryptography，仅在 Enterprise + SAML provider
    实际使用时才导入，避免 Personal 版因缺少 lxml 而无法 import maop.enterprise.sso。
    """
    from maop.enterprise.saml_handler import SAMLHandler
    return SAMLHandler


class SSOManager:
    """Enterprise SSO integration manager.

    会话持久化（P1 #13）：默认内存存储（向后兼容）；传入
    ``session_store`` 或设置 ``MAOP_SSO_SESSION_PERSIST=1`` 时启用
    SQLite 持久化，进程重启不再丢失已登录会话。
    """

    def __init__(
        self,
        config: SSOConfig | None = None,
        session_store: Any = None,
    ) -> None:
        require_feature(FeatureFlag.SSO)
        self._config = config or SSOConfig()
        self._sessions: dict[str, SSOSession] = {}
        # P1 #13: 可选 SQLite 会话持久化（显式传入或环境变量启用）
        if session_store is None:
            from maop.enterprise.sso_session_store import maybe_open_store
            session_store = maybe_open_store()
        self._session_store = session_store
        # SAML 处理器进程级单例（lazy）：InResponseTo 与 Assertion 重放
        # 防护依赖 handler 实例内的 pending/consumed 状态——若每次回调新建
        # handler 则状态表恒空、防护全部失效（v5.2.0 前为死代码，P0 修复）。
        self._saml_handler: Any | None = None

    def _get_saml_handler_instance(self):
        """获取（并缓存）进程内唯一的 SAMLHandler 实例。

        重放防护（``_pending_request_ids`` / ``_consumed_assertion_ids``）
        是 handler 实例内存态，必须跨 authorize/callback 复用同一实例，
        否则 InResponseTo 校验与 Assertion 重放拦截永远命中不到。
        """
        if self._saml_handler is None:
            SAMLHandler = _get_saml_handler()
            self._saml_handler = SAMLHandler(self._config)
        return self._saml_handler

    @property
    def config(self) -> SSOConfig:
        return self._config

    def get_authorize_url(
        self,
        state: str = "",
        code_challenge: str = "",
    ) -> str:
        """构造 IdP authorize URL。

        Args:
            state: OAuth state（防 CSRF），透传给 IdP 并在回调时校验。
            code_challenge: PKCE code_challenge（S256）。若提供则附加
                ``code_challenge_method=S256`` 与 ``code_challenge`` 参数。
                由调用方通过 :func:`generate_pkce_pair` 生成并暂存
                code_verifier（用于 ``handle_callback``）。
        """
        # SAML：构造 AuthnRequest 重定向 URL（由 SAMLHandler 实现）。
        # 复用同一 handler 实例（重放防护状态跨调用保持）。
        if self._config.provider == SSOProvider.SAML:
            handler = self._get_saml_handler_instance()
            return handler.get_authorize_url(state=state)
        if self._config.provider == SSOProvider.OIDC:
            params: dict[str, str] = {
                "client_id": self._config.client_id,
                "redirect_uri": self._config.redirect_uri,
                "response_type": "code",
                "scope": " ".join(self._config.scopes),
            }
            if state:
                params["state"] = state
            # PRD NFR-S03: PKCE 防截码攻击
            if code_challenge:
                params["code_challenge"] = code_challenge
                params["code_challenge_method"] = "S256"
            # P0 fix: 使用 urlencode 正确转义特殊字符（scope 含空格、
            # redirect_uri 含 &/? 等场景下手动 join 会破坏 URL）
            query = urllib.parse.urlencode(params)
            return f"{self._config.authorize_url}?{query}"
        return ""

    def handle_callback(
        self,
        code: str,
        state: str = "",
        code_verifier: str = "",
    ) -> SSOSession:
        """Exchange an OAuth authorization code for tokens and create a session.

        For OIDC: POST to ``SSOConfig.token_url`` with the standard
        ``authorization_code`` grant, parse ``{access_token, refresh_token,
        expires_in, id_token}``, optionally fetch userinfo from
        ``userinfo_url`` with Bearer auth, then build a real ``SSOSession``
        with the returned tokens and expiry. 当 ``code_verifier`` 非空时
        附加 PKCE 参数（PRD NFR-S03）。

        For SAML: ``code`` 是 base64 编码的 SAMLResponse，``state`` 是 RelayState。
        委托给 SAMLHandler.handle_response() 验证 XML 签名、Conditions，
        提取 NameID/Attributes 后构造 SSOSession。

        Args:
            code: Authorization code (OIDC) 或 base64 SAMLResponse (SAML)。
            state: Optional OAuth state value / SAML RelayState。
            code_verifier: PKCE code_verifier（与 authorize 阶段的
                code_challenge 配对）。仅 OIDC 有效。

        Returns:
            A new SSOSession persisted in ``self._sessions``.

        Raises:
            ValueError: ``code`` is empty, or OIDC config is missing
                ``token_url``.
            RuntimeError: Token endpoint returned an error response, a
                non-JSON body, or was unreachable.
            SSOError: SAML 验证失败（签名错误、过期、Audience 不匹配等）。
        """
        if not code:
            raise ValueError("handle_callback: 'code' must not be empty")

        if self._config.provider == SSOProvider.SAML:
            return self._handle_saml_callback(code, state)

        # OIDC: real OAuth authorization_code exchange.
        if not self._config.token_url:
            raise ValueError(
                "SSOConfig.token_url is required for OIDC handle_callback"
            )

        token_resp = self._exchange_code(code, state, code_verifier)
        access_token = str(token_resp.get("access_token", ""))
        refresh_token = str(token_resp.get("refresh_token", ""))
        try:
            expires_in = float(token_resp.get("expires_in", 3600))
        except (TypeError, ValueError):
            logger.warning(
                "[sso] token endpoint returned non-numeric expires_in=%r; "
                "defaulting to 3600",
                token_resp.get("expires_in"),
            )
            expires_in = 3600.0

        now = time.time()

        user_claims: dict[str, Any] = {}
        if access_token and self._config.userinfo_url:
            user_claims = self._fetch_userinfo(access_token)

        user = self._build_user_from_claims(user_claims, token_resp)
        session_id = f"sess_{secrets.token_hex(16)}_{int(now)}"
        session = SSOSession(
            session_id=session_id,
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=now + expires_in,
            created_at=now,
        )
        self._sessions[session_id] = session
        self._persist_session(session)
        logger.info(
            "[sso] OIDC session=%s user=%s expires_in=%ss",
            session_id, user.external_id, int(expires_in),
        )
        return session

    def _persist_session(self, session: SSOSession) -> None:
        """写入会话持久化后端（若启用）。失败仅告警，不阻断登录。"""
        if self._session_store is None:
            return
        try:
            self._session_store.save_session(
                session.model_dump_json(),
                session.session_id,
                session.expires_at,
                session.created_at,
            )
        except Exception as exc:
            logger.warning("[sso] session persist failed (in-memory only): %s", exc)

    def _delete_persisted_session(self, session_id: str) -> None:
        if self._session_store is None:
            return
        try:
            self._session_store.delete_session(session_id)
        except Exception as exc:
            logger.warning("[sso] session delete failed: %s", exc)

    def _exchange_code(
        self,
        code: str,
        state: str,
        code_verifier: str = "",
    ) -> dict[str, Any]:
        """POST authorization_code grant to ``token_url``; return parsed JSON.

        Fail-closed on HTTP errors, network errors, non-JSON responses, and
        OAuth ``error`` fields in the response body.

        当 ``code_verifier`` 非空时附加 PKCE 参数（RFC 7636）。
        """
        form: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._config.redirect_uri,
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
        }
        if code_verifier:
            form["code_verifier"] = code_verifier
        body = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(
            self._config.token_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"SSO token endpoint returned HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"SSO token endpoint unreachable: {exc.reason}"
            ) from exc

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"SSO token endpoint returned non-JSON response: "
                f"{payload[:200]!r}"
            ) from exc

        if not isinstance(parsed, dict):
            raise TypeError(
                f"SSO token endpoint returned non-object JSON: {type(parsed).__name__}"
            )
        if "error" in parsed:
            err = parsed.get("error")
            desc = parsed.get("error_description", "")
            raise RuntimeError(
                f"SSO token endpoint error: {err} — {desc}"
            )
        return parsed

    def _fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """GET ``userinfo_url`` with Bearer auth; return parsed claims.

        Fail-closed (P0 修复)：userinfo 获取失败（网络错误/非 JSON/非对象）
        直接抛 :class:`SSOError` 拒绝登录。旧实现返回 ``{}`` 并降级为
        ``oidc:unknown`` —— 所有 userinfo 不可用期间登录的用户会映射到
        同一 external_id，造成身份合并/可致账号接管。由于本实现不验证
        id_token 签名（无 JWKS），userinfo 是唯一身份依据，失败必须拒绝。
        """
        req = urllib.request.Request(
            self._config.userinfo_url,
            method="GET",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = resp.read().decode("utf-8")
            parsed: Any = json.loads(payload)
            if not isinstance(parsed, dict):
                raise SSOError(
                    f"userinfo endpoint returned non-object JSON: "
                    f"{type(parsed).__name__}"
                )
            return parsed
        except SSOError:
            raise
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            logger.error("[sso] userinfo fetch failed — login rejected: %s", exc)
            raise SSOError(f"userinfo fetch failed: {exc}") from exc

    def _build_user_from_claims(
        self, claims: dict[str, Any], token_resp: dict[str, Any]
    ) -> SSOUser:
        """Construct ``SSOUser`` from IdP claims + token response.

        支持外部属性映射（PRD 3.4）：当 ``SSOConfig.attribute_mapping`` 非空时，
        按映射从 claims 取值；否则使用默认 precedence（向后兼容）。

        Claim precedence (first non-empty wins, 默认无映射时):
          - external_id: ``sub`` | ``user_id``（缺失时抛 :class:`SSOError`
            fail-closed —— 旧实现降级为 "unknown"，会让所有 userinfo 缺失
            sub 的用户映射到同一 external_id，造成身份合并）
          - email: ``email`` | ``email_verified`` (bool -> "")
          - display_name: ``name`` | ``preferred_username`` | ``nickname``
          - roles: ``roles`` (list) | ``role`` (str|list) | ``groups``
          - tenant_id: ``tenant_id`` | ``tid``

        SECURITY NOTE: id_token signature is NOT verified (no JWKS fetch).
        Identity relies on the userinfo endpoint over TLS + access_token.
        TODO: add JWKS-based id_token signature verification.

        Raises:
            SSOError: 无法从 claims 确定唯一身份（sub 缺失）。
        """
        now = time.time()
        mapping = self._config.attribute_mapping or {}

        if mapping:
            sub = self._claim_first(claims, mapping.get("external_id", "sub")) or ""
            # P0 fix: sub 缺失即拒绝 —— 不降级、不从未验签 id_token 截取
            if not sub:
                raise SSOError(
                    "OIDC userinfo response missing subject identifier "
                    f"(claim '{mapping.get('external_id', 'sub')}') — login rejected"
                )
            email = self._claim_first(claims, mapping.get("email", "email"))
            name = self._claim_first(claims, mapping.get("display_name", "name"))
            roles = self._mapped_roles(claims, mapping)
            if not roles:
                roles = [self._config.default_role]
            tenant_id = self._claim_first(claims, mapping.get("tenant_id", "tid"))
            return SSOUser(
                external_id=f"{self._config.provider.value}:{sub}",
                email=str(email or ""),
                display_name=str(name or ""),
                roles=roles,
                tenant_id=str(tenant_id or ""),
                provider=self._config.provider,
                last_login=now,
            )

        # 默认 precedence（向后兼容）
        sub = (
            claims.get("sub")
            or claims.get("user_id")
            or ""
        )
        # P0 fix: sub 缺失即拒绝（不降级 "unknown"，见上方 docstring）
        if not sub:
            raise SSOError(
                "OIDC userinfo response missing 'sub' claim — login rejected"
            )

        email = str(claims.get("email", "") or "")
        name = (
            claims.get("name")
            or claims.get("preferred_username")
            or claims.get("nickname")
            or ""
        )
        roles = self._roles_from_claims(claims)
        if not roles:
            roles = [self._config.default_role]
        tenant_id = (
            claims.get("tenant_id")
            or claims.get("tid")
            or ""
        )
        return SSOUser(
            external_id=f"{self._config.provider.value}:{sub}",
            email=email,
            display_name=str(name),
            roles=roles,
            tenant_id=str(tenant_id),
            provider=self._config.provider,
            last_login=now,
        )

    @staticmethod
    def _claim_first(claims: dict[str, Any], key: str) -> str:
        """按 key 从 claims 取首个非空字符串值（支持 list/tuple 取首元素）。"""
        if not key:
            return ""
        v = claims.get(key)
        if isinstance(v, list) and v:
            return str(v[0])
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v is not None:
            return str(v)
        return ""

    def _mapped_roles(
        self,
        claims: dict[str, Any],
        mapping: dict[str, Any],
    ) -> list[str]:
        """按映射从 claims 提取角色，再按 role_mapping 转换为系统角色。"""
        roles_key = mapping.get("roles", "groups")
        raw: list[str] = []
        v = claims.get(roles_key)
        if isinstance(v, list) and v:
            raw = [str(r) for r in v]
        elif isinstance(v, str) and v.strip():
            raw = [v.strip()]
        role_map = self._config.role_mapping or {}
        if not role_map:
            return raw
        return [role_map.get(r, r) for r in raw]

    def _roles_from_claims(self, claims: dict[str, Any]) -> list[str]:
        """Extract roles from common claim shapes.

        Supports ``roles`` (list), ``role`` (str or list), and ``groups``
        (list). Returns an empty list if none are present (caller applies
        the default role).
        """
        for key in ("roles", "role", "groups"):
            v = claims.get(key)
            if isinstance(v, list) and v:
                return [str(r) for r in v]
            if isinstance(v, str) and v.strip():
                return [v.strip()]
        return []

    def _handle_saml_callback(self, code: str, state: str = "") -> SSOSession:
        """处理 SAML 回调。

        ``code`` 是 base64 编码的 SAMLResponse（HTTP-POST binding），
        ``state`` 是 RelayState（透传回 SP，不参与验证）。

        委托给 SAMLHandler.handle_response()：
          - base64 解码 → 解析 XML
          - 验证 XML 签名（enveloped signature, exclusive c14n, RSA-SHA256）
          - 验证 Conditions（Audience、NotBefore/NotOnOrAfter，±60s 容差）
          - 提取 NameID 和 AttributeStatement
          - 构造 SSOSession

        Raises:
            SSOError: 任何验证失败（fail-closed，绝不返回 stub session）。
        """
        # 复用进程内同一 handler 实例（重放防护状态跨回调保持）
        handler = self._get_saml_handler_instance()
        session = handler.handle_response(code, relay_state=state)
        self._sessions[session.session_id] = session
        self._persist_session(session)
        logger.info(
            "[sso] SAML session=%s user=%s",
            session.session_id, session.user.external_id,
        )
        return session  # type: ignore

    def validate_session(self, session_id: str) -> SSOSession | None:
        session = self._sessions.get(session_id)
        if session is None and self._session_store is not None:
            # P1 #13: 内存未命中 → 尝试持久化后端（重启后恢复会话）
            try:
                raw = self._session_store.get_session_json(session_id)
                if raw:
                    session = SSOSession.model_validate_json(raw)
                    self._sessions[session_id] = session
            except Exception as exc:
                logger.warning("[sso] session load from store failed: %s", exc)
        if not session:
            return None
        if session.expires_at and time.time() > session.expires_at:
            del self._sessions[session_id]
            self._delete_persisted_session(session_id)
            return None
        return session

    def logout(self, session_id: str) -> bool:
        found = session_id in self._sessions
        if found:
            del self._sessions[session_id]
        # P1 #13: 同时处理持久化会话（即使内存中没有也要清后端）
        if self._session_store is not None:
            try:
                if self._session_store.get_session_json(session_id) is not None:
                    found = True
                self._session_store.delete_session(session_id)
            except Exception as exc:
                logger.warning("[sso] session store logout failed: %s", exc)
        return found
