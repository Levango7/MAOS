"""MAOP Enterprise SSO Provider Store — ``sso_providers`` 表 CRUD。

PRD 3.1 schema 的持久化层，支持 SQLite（Personal 开发测试）和
PostgreSQL（Enterprise 生产，通过 :class:`PgSSOProviderStore`）。

敏感字段（``client_secret`` / ``x509_cert``）使用 Fernet 对称加密存储
（PRD NFR-S01 / NFR-S02），复用 :class:`ApiKeyVault` 的主密钥体系
（``MAOP_KEY`` / ``MAOP_KEY_FILE`` / 自动生成 ``data/.enc_key``）。

非敏感配置（authorize_url、token_url 等）以明文 JSON 存入 ``config`` 列。
API 响应时通过 :func:`mask_sensitive_fields` 脱敏（PRD NFR-S07）。
"""

from __future__ import annotations

import builtins
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature
from maop.core.backends.db_utils import get_db_path, sqlite_connect

logger = logging.getLogger(__name__)


# ── 敏感字段识别 ─────────────────────────────────────────────────────
# OIDC: client_secret；SAML: x509_cert。请求体中用明文 key（无 _enc 后缀），
# 存储时加密并改名为 *_enc，响应时返回 "***"。
SENSITIVE_KEYS: tuple[str, ...] = ("client_secret", "x509_cert")
SENSITIVE_MASK = "***"


def mask_sensitive_fields(config: dict[str, Any]) -> dict[str, Any]:
    """脱敏：将敏感字段值替换为 ``"***"``，并展开 ``*_enc`` 为原名。

    用于 API 响应（PRD NFR-S07）：``client_secret_enc`` → ``client_secret="***"``，
    ``x509_cert_enc`` → ``x509_cert="***"``，绝不回传明文。
    """
    masked: dict[str, Any] = {}
    for k, v in config.items():
        if k.endswith("_enc"):
            base = k[:-4]
            if base in SENSITIVE_KEYS:
                masked[base] = SENSITIVE_MASK
                continue
        if k in SENSITIVE_KEYS:
            masked[k] = SENSITIVE_MASK
            continue
        masked[k] = v
    return masked


# ── Fernet 加密 helper（复用 ApiKeyVault 主密钥） ────────────────────
def _get_fernet() -> Any:
    """获取 Fernet 实例（复用 ApiKeyVault 的主密钥解析逻辑）。

    若 cryptography 未安装或密钥不可用，返回 None（降级为明文 + 警告）。
    """
    try:
        from cryptography.fernet import Fernet  # noqa: F401
    except ImportError:
        logger.warning("[sso_store] cryptography not installed — secrets stored in plaintext")
        return None
    try:
        from maop.core.security.api_key_vault import ApiKeyVault
        vault = ApiKeyVault()
        return vault._fernet
    except Exception as exc:  # pragma: no cover — 防御性
        logger.warning("[sso_store] Cannot obtain Fernet from ApiKeyVault: %s", exc)
        return None


def _encrypt_secret(plaintext: str) -> str:
    """加密单个敏感字段。返回 ``<enc:...>`` 标记的密文或明文（降级）。"""
    if not plaintext:
        return ""
    fernet = _get_fernet()
    if fernet is None:
        return plaintext  # 降级：明文存储 + 已有警告
    try:
        return str(fernet.encrypt(plaintext.encode("utf-8")).decode("ascii"))
    except Exception as exc:  # pragma: no cover
        logger.warning("[sso_store] encrypt failed: %s", exc)
        return plaintext


def _decrypt_secret(ciphertext: str) -> str:
    """解密单个敏感字段。"""
    if not ciphertext:
        return ""
    fernet = _get_fernet()
    if fernet is None:
        return ciphertext
    try:
        return str(fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        logger.warning("[sso_store] decrypt failed: %s", exc)
        return ""


def _encrypt_config(config: dict[str, Any]) -> dict[str, Any]:
    """加密 config 中的敏感字段，输出存储格式（``*_enc`` 后缀）。"""
    out: dict[str, Any] = {}
    for k, v in config.items():
        if k in SENSITIVE_KEYS and isinstance(v, str) and v:
            out[f"{k}_enc"] = _encrypt_secret(v)
        else:
            out[k] = v
    return out


def _decrypt_config(config: dict[str, Any]) -> dict[str, Any]:
    """解密 config 中的 ``*_enc`` 字段，输出明文格式（去掉后缀）。"""
    out: dict[str, Any] = {}
    for k, v in config.items():
        if k.endswith("_enc"):
            base = k[:-4]
            if base in SENSITIVE_KEYS and isinstance(v, str) and v:
                out[base] = _decrypt_secret(v)
                continue
        out[k] = v
    return out


# ── Pydantic 模型（PRD 4.2.1） ───────────────────────────────────────



class SSOProviderCreate(BaseModel):
    """创建 IdP 请求模型（PRD 4.2.1）。"""

    name: str = Field(min_length=1, max_length=100)
    protocol: str = Field(pattern=r"^(oidc|saml)$")
    tenant_id: str = Field(default="", max_length=100)
    enabled: bool = True
    auto_redirect: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    attribute_mapping: dict[str, Any] = Field(default_factory=dict)


class SSOProviderUpdate(BaseModel):
    """更新 IdP 请求模型（部分更新；空字段表示不修改）。"""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    tenant_id: str | None = Field(default=None, max_length=100)
    enabled: bool | None = None
    auto_redirect: bool | None = None
    config: dict[str, Any] | None = None
    attribute_mapping: dict[str, Any] | None = None


class SSOProviderResponse(BaseModel):
    """IdP 响应模型（敏感字段已脱敏）。"""

    id: int
    name: str
    protocol: str
    tenant_id: str = ""
    enabled: bool = True
    auto_redirect: bool = False
    config: dict[str, Any] = Field(default_factory=dict)
    attribute_mapping: dict[str, Any] = Field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0


# ── SSOProviderStore ────────────────────────────────────────────────
class SSOProviderStore:
    """``sso_providers`` 表 CRUD（SQLite 后端，PRD 3.1）。

    Personal 版/开发环境使用 SQLite（unified ``maop.db``）。
    Enterprise 生产环境通过 :class:`PgSSOProviderStore` 走 PostgreSQL
    （见 :mod:`maop.enterprise.pg_persist`）。

    所有敏感字段在写入前加密、读出后解密；API 响应前由调用方
    调用 :func:`mask_sensitive_fields` 脱敏。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        require_feature(FeatureFlag.SSO)
        self._db_path = Path(db_path) if db_path else get_db_path("sso_providers")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """建表 + 索引（PRD 3.1）。SQLite 用 TEXT 存 JSON。"""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite_connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sso_providers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    tenant_id TEXT DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    auto_redirect INTEGER NOT NULL DEFAULT 0,
                    config TEXT DEFAULT '{}',
                    attribute_mapping TEXT DEFAULT '{}',
                    created_at REAL NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0,
                    UNIQUE(name, tenant_id)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sso_providers_tenant ON sso_providers(tenant_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sso_providers_enabled ON sso_providers(enabled)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sso_providers_protocol ON sso_providers(protocol)"
            )

    # ── CRUD ───────────────────────────────────────────────────────
    def create(self, data: SSOProviderCreate) -> SSOProviderResponse:
        """插入一条 IdP 配置。敏感字段加密后存储。

        Raises:
            ValueError: 同租户下 name 重复（UNIQUE 约束）。
        """
        now = time.time()
        config_enc = _encrypt_config(data.config)
        with sqlite_connect(self._db_path) as conn:
            try:
                cur = conn.execute(
                    """INSERT INTO sso_providers
                       (name, protocol, tenant_id, enabled, auto_redirect,
                        config, attribute_mapping, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        data.name,
                        data.protocol,
                        data.tenant_id,
                        int(data.enabled),
                        int(data.auto_redirect),
                        json.dumps(config_enc),
                        json.dumps(data.attribute_mapping),
                        now,
                        now,
                    ),
                )
            except Exception as exc:
                if "UNIQUE" in str(exc).upper():
                    raise ValueError(
                        f"SSO provider name conflict: {data.name!r} in tenant {data.tenant_id!r}"
                    ) from exc
                raise
            new_id = int(cur.lastrowid or 0)
        return self.get(new_id)  # type: ignore

    def get(self, provider_id: int) -> SSOProviderResponse | None:
        """按 ID 查询；返回明文 config（已解密）。"""
        with sqlite_connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM sso_providers WHERE id=?",
                (provider_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_response(row)

    def list(
        self,
        *,
        protocol: str = "",
        enabled: bool | None = None,
        tenant_id: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SSOProviderResponse], int]:
        """列出 IdP（带过滤 + 分页）。返回 (rows, total)。"""
        clauses: list[str] = []
        params: list[Any] = []
        if protocol:
            clauses.append("protocol=?")
            params.append(protocol)
        if enabled is not None:
            clauses.append("enabled=?")
            params.append(int(enabled))
        if tenant_id:
            clauses.append("(tenant_id=? OR tenant_id='')")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with sqlite_connect(self._db_path) as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) AS n FROM sso_providers {where}",
                tuple(params),
            ).fetchone()
            total = int(total_row["n"] if total_row else 0)
            rows = conn.execute(
                f"""SELECT * FROM sso_providers {where}
                    ORDER BY id DESC LIMIT ? OFFSET ?""",
                (*params, limit, offset),
            ).fetchall()
        return [self._row_to_response(r) for r in rows], total

    def update(
        self,
        provider_id: int,
        data: SSOProviderUpdate,
    ) -> SSOProviderResponse | None:
        """部分更新。``config`` 中的敏感字段若为空字符串则不修改。

        Raises:
            ValueError: name 改为同租户下已存在的名称。
            KeyError: provider_id 不存在。
        """
        existing = self.get(provider_id)
        if existing is None:
            return None

        new_name = data.name if data.name is not None else existing.name
        new_tenant = data.tenant_id if data.tenant_id is not None else existing.tenant_id
        new_enabled = int(data.enabled) if data.enabled is not None else int(existing.enabled)
        new_auto = (
            int(data.auto_redirect)
            if data.auto_redirect is not None
            else int(existing.auto_redirect)
        )

        if data.config is not None:
            # 合并：保留旧 config 中未传的字段；敏感字段空串表示不修改
            merged: dict[str, Any] = dict(existing.config)
            for k, v in data.config.items():
                if k in SENSITIVE_KEYS and v == "":
                    # 空串 = 不修改（保留旧值）
                    continue
                merged[k] = v
            config_enc = _encrypt_config(merged)
        else:
            config_enc = _encrypt_config(existing.config)

        new_mapping = (
            data.attribute_mapping
            if data.attribute_mapping is not None
            else existing.attribute_mapping
        )

        now = time.time()
        with sqlite_connect(self._db_path) as conn:
            try:
                cur = conn.execute(
                    """UPDATE sso_providers
                       SET name=?, tenant_id=?, enabled=?, auto_redirect=?,
                           config=?, attribute_mapping=?, updated_at=?
                       WHERE id=?""",
                    (
                        new_name,
                        new_tenant,
                        new_enabled,
                        new_auto,
                        json.dumps(config_enc),
                        json.dumps(new_mapping),
                        now,
                        provider_id,
                    ),
                )
            except Exception as exc:
                if "UNIQUE" in str(exc).upper():
                    raise ValueError(
                        f"SSO provider name conflict: {new_name!r} in tenant {new_tenant!r}"
                    ) from exc
                raise
            if cur.rowcount == 0:
                return None
        return self.get(provider_id)

    def delete(self, provider_id: int) -> bool:
        """按 ID 删除。返回是否删除成功。"""
        with sqlite_connect(self._db_path) as conn:
            cur = conn.execute(
                "DELETE FROM sso_providers WHERE id=?",
                (provider_id,),
            )
            return cur.rowcount > 0

    def list_enabled(self) -> builtins.list[SSOProviderResponse]:
        """列出所有启用的 IdP（用于登录页渲染按钮，PRD 4.2.5）。"""
        rows, _ = self.list(enabled=True, limit=500)
        return rows

    # ── helpers ────────────────────────────────────────────────────
    @staticmethod
    def _row_to_response(row: Any) -> SSOProviderResponse:
        """sqlite3.Row → SSOProviderResponse（解密敏感字段）。"""
        config_raw = row["config"] or "{}"
        mapping_raw = row["attribute_mapping"] or "{}"
        try:
            config_stored = json.loads(config_raw)
        except json.JSONDecodeError:
            config_stored = {}
        try:
            mapping = json.loads(mapping_raw)
        except json.JSONDecodeError:
            mapping = {}
        config_plain = _decrypt_config(config_stored)
        return SSOProviderResponse(
            id=int(row["id"]),
            name=str(row["name"]),
            protocol=str(row["protocol"]),
            tenant_id=str(row["tenant_id"] or ""),
            enabled=bool(row["enabled"]),
            auto_redirect=bool(row["auto_redirect"]),
            config=config_plain,
            attribute_mapping=mapping,
            created_at=float(row["created_at"] or 0.0),
            updated_at=float(row["updated_at"] or 0.0),
        )


# ── 启动时从环境变量导入单 IdP 配置（PRD NFR-C03 向后兼容） ──────────
def import_env_provider_if_present(store: SSOProviderStore) -> int | None:
    """若 ``MAOP_SSO_CLIENT_ID`` 等环境变量存在，导入为一条 sso_providers 记录。

    用于向后兼容现有单 IdP 环境变量配置（PRD NFR-C03）。
    仅在表为空时执行，避免重复导入。返回新记录 id 或 None。
    """
    rows, _ = store.list(limit=1)
    if rows:
        return None  # 已有配置，不自动导入

    client_id = os.getenv("MAOP_SSO_CLIENT_ID", "").strip()
    if not client_id:
        return None

    protocol = os.getenv("MAOP_SSO_PROVIDER", "oidc").strip().lower()
    if protocol not in ("oidc", "saml"):
        protocol = "oidc"

    name = os.getenv("MAOP_SSO_NAME", "Default IdP").strip() or "Default IdP"
    client_secret = os.getenv("MAOP_SSO_CLIENT_SECRET", "")
    authorize_url = os.getenv("MAOP_SSO_AUTHORIZE_URL", "")
    token_url = os.getenv("MAOP_SSO_TOKEN_URL", "")
    userinfo_url = os.getenv("MAOP_SSO_USERINFO_URL", "")
    redirect_uri = os.getenv("MAOP_SSO_REDIRECT_URI", "")
    scopes_str = os.getenv("MAOP_SSO_SCOPES", "openid profile email")
    scopes = [s.strip() for s in scopes_str.split(",") if s.strip()]

    config: dict[str, Any] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "authorize_url": authorize_url,
        "token_url": token_url,
        "userinfo_url": userinfo_url,
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "use_pkce": True,
    }
    if protocol == "saml":
        config.update(
            {
                "entity_id": os.getenv("MAOP_SSO_SAML_SP_ENTITY_ID", "maop-sp"),
                "sso_url": authorize_url,
                "acs_url": os.getenv("MAOP_SSO_SAML_ACS_URL", redirect_uri),
                "x509_cert": os.getenv("MAOP_SSO_SAML_IDP_CERT", ""),
            }
        )

    try:
        resp = store.create(
            SSOProviderCreate(
                name=name,
                protocol=protocol,
                config=config,
            )
        )
        logger.info("[sso_store] Imported env-based SSO provider id=%s name=%s", resp.id, resp.name)
        return resp.id
    except Exception as exc:  # pragma: no cover — 防御性
        logger.warning("[sso_store] Failed to import env SSO provider: %s", exc)
        return None


__all__ = [
    "SENSITIVE_KEYS",
    "SENSITIVE_MASK",
    "SSOProviderCreate",
    "SSOProviderResponse",
    "SSOProviderStore",
    "SSOProviderUpdate",
    "import_env_provider_if_present",
    "mask_sensitive_fields",
]