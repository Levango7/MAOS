"""MAOP Enterprise RBAC — Role-Based Access Control.

Extends core/auth.py with hierarchical roles, permission grants,
and resource-level access control for multi-user environments.

Role hierarchy:
  superadmin > admin > operator > viewer

Permission model:
  resource:action  (e.g. "agents:read", "config:write", "tenant:admin")
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


class Role(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(str, Enum):
    AGENTS_READ = "agents:read"
    AGENTS_WRITE = "agents:write"
    AGENTS_EXECUTE = "agents:execute"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    MODELS_READ = "models:read"
    MODELS_WRITE = "models:write"
    COST_READ = "cost:read"
    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    TENANT_ADMIN = "tenant:admin"
    AUDIT_READ = "audit:read"
    RBAC_READ = "rbac:read"
    RBAC_WRITE = "rbac:write"
    SYSTEM_ADMIN = "system:admin"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SUPERADMIN: frozenset(Permission),
    Role.ADMIN: frozenset(set(Permission) - {Permission.TENANT_ADMIN, Permission.SYSTEM_ADMIN}),
    Role.OPERATOR: frozenset({
        Permission.AGENTS_READ, Permission.AGENTS_WRITE, Permission.AGENTS_EXECUTE,
        Permission.CONFIG_READ, Permission.MEMORY_READ, Permission.MEMORY_WRITE,
        Permission.MODELS_READ, Permission.COST_READ,
    }),
    Role.VIEWER: frozenset({
        Permission.AGENTS_READ, Permission.CONFIG_READ, Permission.MEMORY_READ,
        Permission.MODELS_READ, Permission.COST_READ,
    }),
}


class RoleGrant(BaseModel):
    user_id: str
    role: Role
    tenant_id: str = ""
    granted_by: str = ""
    granted_at: float = 0.0
    expires_at: float | None = None


class SqliteRBACStore:
    """SQLite-backed RBAC grant persistence (P1 #12).

    PostgreSQL 不可用时的持久化兜底（此前仅内存，进程重启授权全丢）。
    接口与 :class:`maop.enterprise.pg_persist.PgRBACStore` 对齐，schema
    保持一致：``UNIQUE(user_id, role, tenant_id)`` + upsert 语义。

    数据库文件：``$MAOP_DATA_DIR/rbac.db``（默认 ``data/rbac.db``）。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            data_dir = Path(os.getenv("MAOP_DATA_DIR", "data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "rbac.db"
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._ok = True
        try:
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rbac_grants (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        tenant_id TEXT DEFAULT '',
                        granted_by TEXT DEFAULT '',
                        granted_at REAL DEFAULT 0,
                        expires_at REAL DEFAULT NULL,
                        UNIQUE(user_id, role, tenant_id)
                    )
                """)
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_rbac_user ON rbac_grants(user_id)"
                )
        except Exception as exc:
            self._ok = False
            logger.warning("[rbac] SQLite store unavailable: %s", exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @property
    def available(self) -> bool:
        return self._ok

    def save_grant(
        self,
        user_id: str,
        role: str,
        tenant_id: str,
        granted_by: str,
        granted_at: float,
        expires_at: float | None,
    ) -> None:
        if not self._ok:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO rbac_grants
                      (user_id, role, tenant_id, granted_by, granted_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (user_id, role, tenant_id) DO UPDATE SET
                      granted_by=excluded.granted_by,
                      granted_at=excluded.granted_at,
                      expires_at=excluded.expires_at""",
                (user_id, role, tenant_id, granted_by, granted_at, expires_at),
            )

    def delete_grant(self, user_id: str, role: str, tenant_id: str) -> bool:
        if not self._ok:
            return False
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM rbac_grants WHERE user_id=? AND role=? AND tenant_id=?",
                (user_id, role, tenant_id),
            )
        return True

    def load_grants(self, user_id: str = "", tenant_id: str = "") -> list[dict[str, Any]]:
        if not self._ok:
            return []
        if user_id and tenant_id:
            sql = ("SELECT * FROM rbac_grants WHERE user_id=? "
                   "AND (tenant_id=? OR tenant_id='')")
            params: tuple = (user_id, tenant_id)
        elif user_id:
            sql = "SELECT * FROM rbac_grants WHERE user_id=?"
            params = (user_id,)
        elif tenant_id:
            sql = "SELECT * FROM rbac_grants WHERE tenant_id=? OR tenant_id=''"
            params = (tenant_id,)
        else:
            sql = "SELECT * FROM rbac_grants"
            params = ()
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


class RBACManager:
    """Enterprise RBAC permission checker.

    持久化优先级（P1 #12）：PostgreSQL > SQLite > 内存（仅测试兜底）。

    Parameters
    ----------
    sqlite_store : SqliteRBACStore | None
        显式指定 SQLite store（如测试用 tmp 路径）。None 时按
        ``enable_sqlite_fallback`` 决定是否创建默认 store。
    enable_sqlite_fallback : bool
        PG 不可用时是否启用默认 SQLite 兜底（``data/rbac.db``）。
        测试可传 False 获得纯内存隔离实例。
    """

    def __init__(
        self,
        *,
        sqlite_store: SqliteRBACStore | None = None,
        enable_sqlite_fallback: bool = True,
    ) -> None:
        require_feature(FeatureFlag.RBAC)
        self._grants: list[RoleGrant] = []
        self._pg: PgRBACStore | None = None
        self._sqlite: SqliteRBACStore | None = None
        try:
            from maop.enterprise.pg_persist import PgRBACStore
            pg = PgRBACStore()
            if pg.available:
                self._pg = pg
        except Exception as e:
            logger.debug("ignored: %s", e, exc_info=True)
        if self._pg is None:
            if sqlite_store is not None:
                self._sqlite = sqlite_store
            elif enable_sqlite_fallback:
                try:
                    store = SqliteRBACStore()
                    if store.available:
                        self._sqlite = store
                        logger.info(
                            "[rbac] using SQLite store at %s (PG unavailable)",
                            store.db_path,
                        )
                except Exception as e:
                    logger.warning("[rbac] SQLite fallback failed: %s", e)
        self._load_from_store()

    def _load_from_store(self) -> None:
        store = self._pg or self._sqlite
        if store is None or not store.available:
            return
        for row in store.load_grants():
            try:
                role = Role(row.get("role", "viewer"))
            except ValueError:
                logger.warning("[rbac] skipping grant with unknown role: %r", row.get("role"))
                continue
            self._grants.append(RoleGrant(
                user_id=row.get("user_id", ""),
                role=role,
                tenant_id=row.get("tenant_id", ""),
                granted_by=row.get("granted_by", ""),
                granted_at=row.get("granted_at", 0.0),
                expires_at=row.get("expires_at"),
            ))

    def grant_role(
        self,
        user_id: str,
        role: Role,
        *,
        granted_by: str = "",
        tenant_id: str = "",
        expires_at: float | None = None,
    ) -> RoleGrant:
        """Grant a role to a user.

        C8 note: authorization is enforced at the HTTP layer
        (dashboard/routers/rbac.py require_admin). Callers invoking this
        method directly MUST perform their own authorization check.
        """
        import time as _time
        now = _time.time()
        # C8 fix: expires_at was accepted by the model but never settable
        # here nor persisted — temporary grants silently became permanent.
        grant = RoleGrant(
            user_id=user_id, role=role, tenant_id=tenant_id,
            granted_by=granted_by, granted_at=now, expires_at=expires_at,
        )
        # P1 #12: 内存去重 —— 与 DB 的 UNIQUE(user_id, role, tenant_id) upsert
        # 语义对齐（旧实现直接 append，重复授权会在 user_roles 中重复出现）
        self._grants = [
            g for g in self._grants
            if not (g.user_id == user_id and g.role == role and g.tenant_id == tenant_id)
        ]
        self._grants.append(grant)
        store = self._pg or self._sqlite
        if store is not None and store.available:
            try:
                store.save_grant(user_id, role.value, tenant_id, granted_by, now, expires_at)
            except Exception as exc:
                logger.warning("[rbac] persist grant failed (in-memory only): %s", exc)
        logger.info("[rbac] Granted %s to user=%s tenant=%s by=%s expires_at=%s",
                    role.value, user_id, tenant_id, granted_by, expires_at)
        return grant

    def revoke_role(self, user_id: str, role: Role, tenant_id: str = "") -> bool:
        before = len(self._grants)
        self._grants = [
            g for g in self._grants
            if not (g.user_id == user_id and g.role == role and g.tenant_id == tenant_id)
        ]
        removed = before - len(self._grants)
        if removed:
            store = self._pg or self._sqlite
            if store is not None and store.available:
                try:
                    store.delete_grant(user_id, role.value, tenant_id)
                except Exception as exc:
                    logger.warning("[rbac] persist revoke failed: %s", exc)
            logger.info("[rbac] Revoked %s from user=%s tenant=%s", role.value, user_id, tenant_id)
        return removed > 0

    @staticmethod
    def _is_active(grant: RoleGrant) -> bool:
        """C8 fix: expired grants must not confer roles/permissions."""
        if grant.expires_at is None:
            return True
        import time as _time
        return grant.expires_at > _time.time()

    def user_roles(self, user_id: str, tenant_id: str = "") -> list[Role]:
        """返回用户在某租户下的角色。

        租户隔离（P0 修复）：``tenant_id`` 为空时**只匹配全局授权**
        （``tenant_id=''`` 的 grant），不再合并该用户在所有租户下的角色。
        旧实现 ``not tenant_id or ...`` 在未显式传租户时会把用户在每个
        租户的授权全部合并——跨租户权限泄漏的入口。
        """
        return [
            g.role for g in self._grants
            if g.user_id == user_id
            and g.tenant_id in ("", tenant_id)
            and self._is_active(g)
        ]

    def user_permissions(self, user_id: str, tenant_id: str = "") -> frozenset[Permission]:
        roles = self.user_roles(user_id, tenant_id)
        perms: set[Permission] = set()
        for r in roles:
            perms |= ROLE_PERMISSIONS.get(r, frozenset())
        return frozenset(perms)

    def has_permission(self, user_id: str, permission: Permission, tenant_id: str = "") -> bool:
        return permission in self.user_permissions(user_id, tenant_id)

    def require_permission(self, user_id: str, permission: Permission, tenant_id: str = "") -> None:
        if not self.has_permission(user_id, permission, tenant_id):
            raise PermissionDenied(user_id, permission, tenant_id)

    def list_grants(self, user_id: str = "", tenant_id: str = "") -> list[RoleGrant]:
        # C8 fix: filter out expired grants so admin views reflect reality.
        result = [g for g in self._grants if self._is_active(g)]
        if user_id:
            result = [g for g in result if g.user_id == user_id]
        if tenant_id:
            result = [g for g in result if g.tenant_id in ("", tenant_id)]
        return result


class PermissionDenied(Exception):
    def __init__(self, user_id: str, permission: Permission, tenant_id: str) -> None:
        self.user_id = user_id
        self.permission = permission
        self.tenant_id = tenant_id
        super().__init__(f"User '{user_id}' lacks permission '{permission.value}' on tenant '{tenant_id}'")
