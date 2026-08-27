"""MAOP Enterprise SSO Session/PKCE Persistence (P1 #13).

SSOManager 的会话表与 SSOProviderRegistry 的 PKCE/state 暂存此前仅存在
内存中：进程重启即全部失效（用户被登出、进行中的 OIDC 登录回调失败），
多副本部署下回调落到另一副本必然 state mismatch。

本模块提供 SQLite 持久化后端（``$MAOP_DATA_DIR/sso_sessions.db``）：

  - ``sso_sessions``       — SSO 会话（JSON 序列化完整会话对象）
  - ``sso_pending_states`` — OIDC authorize 阶段的 (state → provider_id,
    code_verifier, created_at)，带 TTL 清理

启用方式：
  - 显式传入：``SSOManager(config, session_store=SqliteSSOStore())``
  - 环境变量：``MAOP_SSO_SESSION_PERSIST=1``（或指定 .db 路径）时
    SSOManager / SSOProviderRegistry 自动启用 SQLite 后端

**多副本限制**：SQLite 仅解决单实例重启持久化。跨副本共享会话/PKCE
状态需要 Redis 等集中式后端（TODO：实现 ``RedisSSOStore``，接口与
本模块对齐）。
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class SqliteSSOStore:
    """SQLite-backed SSO session + PKCE state store.

    线程安全（RLock + 每操作独立连接，WAL 模式），与 notification store
    同一模板。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            data_dir = Path(os.getenv("MAOP_DATA_DIR", "data"))
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "sso_sessions.db"
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._ok = True
        try:
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sso_sessions (
                        session_id TEXT PRIMARY KEY,
                        session_json TEXT NOT NULL,
                        expires_at REAL NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL DEFAULT 0
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sso_pending_states (
                        state TEXT PRIMARY KEY,
                        provider_id INTEGER NOT NULL,
                        code_verifier TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL DEFAULT 0
                    )
                """)
        except Exception as exc:
            self._ok = False
            logger.warning("[sso_store_persist] SQLite store unavailable: %s", exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @property
    def available(self) -> bool:
        return self._ok

    # ── sessions ─────────────────────────────────────────────────

    def save_session(self, session_json: str, session_id: str,
                     expires_at: float, created_at: float) -> None:
        if not self._ok:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO sso_sessions
                   (session_id, session_json, expires_at, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     session_json=excluded.session_json,
                     expires_at=excluded.expires_at""",
                (session_id, session_json, expires_at, created_at),
            )

    def get_session_json(self, session_id: str) -> str | None:
        if not self._ok:
            return None
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT session_json FROM sso_sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
        return row[0] if row else None

    def delete_session(self, session_id: str) -> bool:
        if not self._ok:
            return False
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sso_sessions WHERE session_id=?", (session_id,)
            )
            return cur.rowcount > 0

    def purge_expired_sessions(self) -> int:
        """删除已过期的会话行（由调用方定期触发）。"""
        if not self._ok:
            return 0
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sso_sessions WHERE expires_at > 0 AND expires_at < ?",
                (time.time(),),
            )
            return cur.rowcount

    # ── pending PKCE/state ───────────────────────────────────────

    def save_pending(self, state: str, provider_id: int,
                     code_verifier: str, created_at: float) -> None:
        if not self._ok:
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO sso_pending_states
                   (state, provider_id, code_verifier, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(state) DO UPDATE SET
                     provider_id=excluded.provider_id,
                     code_verifier=excluded.code_verifier,
                     created_at=excluded.created_at""",
                (state, provider_id, code_verifier, created_at),
            )

    def pop_pending(self, state: str) -> tuple[int, str, float] | None:
        """原子取出并删除 state 条目。返回 (provider_id, code_verifier, created_at)。"""
        if not self._ok:
            return None
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT provider_id, code_verifier, created_at "
                "FROM sso_pending_states WHERE state=?",
                (state,),
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM sso_pending_states WHERE state=?", (state,))
        return int(row[0]), str(row[1]), float(row[2])

    def gc_pending(self, ttl_s: float) -> int:
        """删除超过 TTL 的 state 条目。"""
        if not self._ok:
            return 0
        cutoff = time.time() - ttl_s
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sso_pending_states WHERE created_at < ?", (cutoff,)
            )
            return cur.rowcount


def maybe_open_store(env_value: str | None = None) -> SqliteSSOStore | None:
    """根据环境变量决定是否启用 SQLite 持久化（P1 #13）。

    ``MAOP_SSO_SESSION_PERSIST`` 为空/0 → None（保持内存行为，向后兼容）；
    ``=1`` → 默认路径；其他值 → 作为 .db 文件路径。
    """
    val = (env_value if env_value is not None
           else os.getenv("MAOP_SSO_SESSION_PERSIST", "")).strip()
    if not val or val.lower() in ("0", "false", "no"):
        return None
    try:
        store = SqliteSSOStore(None if val in ("1", "true", "yes") else val)
        if store.available:
            logger.info("[sso_store_persist] SQLite persistence enabled: %s", store.db_path)
            return store
    except Exception as exc:
        logger.warning("[sso_store_persist] failed to open store: %s", exc)
    return None


__all__ = ["SqliteSSOStore", "maybe_open_store"]
