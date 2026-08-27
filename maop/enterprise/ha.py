"""MAOP Enterprise High Availability.

Phase 3.4 implementation: distributed coordination via Redis lease.

When Redis is available (MAOP_HA_BACKEND=redis):
  - Leader election via SET NX EX lease with fencing tokens
  - Automatic failover when leader lease expires
  - Split-brain protection via fencing tokens
  - TODO(P1 #24): cross-process cluster state sync via Redis pub/sub
    is NOT implemented yet — node registry/heartbeats are currently
    per-process; only the leader lease is shared across processes.

When Redis is unavailable:
  - Falls back to single-instance in-memory mode (Phase 3.2 behavior)
  - Leader election via deterministic node_id ordering
  - No cross-process coordination

Configuration:
  - MAOP_HA_BACKEND=redis|memory (default: memory for backward compat)
  - MAOP_REDIS_URL or MAOP_REDIS_HOST/PORT for Redis connection
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from maop.config.edition import FeatureFlag, require_feature
from maop.core.backends.backends_redis import RedisDistributedLock

logger = logging.getLogger(__name__)


class NodeRole(str, Enum):
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"


class NodeStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"


class ClusterNode(BaseModel):
    node_id: str
    address: str
    role: NodeRole = NodeRole.FOLLOWER
    status: NodeStatus = NodeStatus.HEALTHY
    last_heartbeat: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class HAConfig(BaseModel):
    lease_ttl_s: float = 15.0
    heartbeat_interval_s: float = 5.0
    failover_timeout_s: float = 30.0
    min_healthy_nodes: int = 1
    auto_failover: bool = True


def _default_node_id() -> str:
    """Generate a unique node id from hostname and pid."""
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return f"{host}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


class HAManager:
    """Enterprise high availability coordinator.

    Phase 3.4: supports Redis lease-based leader election with fencing
    tokens when MAOP_HA_BACKEND=redis. Falls back to single-instance
    in-memory mode (Phase 3.2 behavior) otherwise.

    线程安全（P3-3 修复）：
        所有对 ``_nodes`` / ``_leader_id`` / ``_redis_mode`` 等共享状态的
        访问都通过 ``_state_lock`` (threading.RLock) 保护。RLock 允许
        嵌套调用（如 ``elect_leader`` → ``_elect_leader_memory``）。
        ``_lock`` 仍然是 RedisDistributedLock 实例（分布式锁），与本地的
        ``_state_lock`` 职责不同，不可混淆。
    """

    def __init__(
        self,
        config: HAConfig | None = None,
        *,
        redis_client: Any = None,
        node_id: str = "",
    ) -> None:
        require_feature(FeatureFlag.MULTI_USER)
        self._config = config or HAConfig()
        self._nodes: dict[str, ClusterNode] = {}
        self._leader_id: str = ""
        # Distributed mode state
        self._redis_mode = os.getenv("MAOP_HA_BACKEND", "memory").lower() == "redis"
        self._redis_client = redis_client
        self._node_id = node_id or _default_node_id()
        self._lock: Any = None  # RedisDistributedLock 实例（分布式锁），懒加载
        self._fencing_token: int = 0
        # 本地状态锁：保护 _nodes / _leader_id / _redis_mode 等共享状态，
        # 避免后台健康监控线程与主线程并发修改导致
        # RuntimeError: dictionary changed size during iteration。
        # 使用 RLock 因为方法会嵌套调用（如 elect_leader → _elect_leader_memory）。
        self._state_lock = threading.RLock()
        # Health monitor state
        self._monitor_thread: threading.Thread | None = None
        self._monitor_stop = threading.Event()
        # P1 #24: 节点注册鉴权钩子（可选）——register_node 前调用，
        # 返回 False 拒绝注册。默认 None 表示不鉴权（向后兼容）。
        self._node_auth_callback: Any = None

    def set_node_authenticator(self, callback: Any) -> None:
        """设置节点注册鉴权回调（P1 #24）。

        ``callback(node_id: str, address: str) -> bool``；返回 False 时
        :meth:`register_node` 抛 ``PermissionError``。传入 None 关闭鉴权。
        """
        self._node_auth_callback = callback

    @property
    def config(self) -> HAConfig:
        return self._config

    @property
    def leader_id(self) -> str:
        with self._state_lock:
            return self._leader_id

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def fencing_token(self) -> int:
        with self._state_lock:
            return self._fencing_token

    def _ensure_lock(self) -> Any:
        """Lazily create the RedisDistributedLock for leader election.

        Returns None and degrades to memory mode if Redis is unavailable.
        """
        if self._lock is not None:
            return self._lock
        try:
            self._lock = RedisDistributedLock(
                "maop_leader",
                ttl=self._config.lease_ttl_s,
                client=self._redis_client,
            )
        except ImportError:
            logger.warning(
                "[ha] Redis backend not available, falling back to memory mode"
            )
            with self._state_lock:
                self._redis_mode = False
            return None
        return self._lock

    def register_node(self, node_id: str, address: str) -> ClusterNode:
        # P1 #24: 鉴权钩子 —— 旧实现任何调用方都能注册节点进入集群
        if self._node_auth_callback is not None:
            try:
                allowed = bool(self._node_auth_callback(node_id, address))
            except Exception as exc:
                logger.warning("[ha] node auth callback error, denying: %s", exc)
                allowed = False
            if not allowed:
                raise PermissionError(
                    f"Node registration rejected by authenticator: node={node_id}"
                )
        with self._state_lock:
            node = ClusterNode(node_id=node_id, address=address, last_heartbeat=time.time())
            self._nodes[node_id] = node
        logger.info("[ha] Registered node=%s address=%s", node_id, address)
        return node

    def deregister_node(self, node_id: str) -> bool:
        with self._state_lock:
            if node_id not in self._nodes:
                return False
            del self._nodes[node_id]
            if self._leader_id == node_id:
                self._leader_id = ""
                logger.warning("[ha] Leader node=%s deregistered — election needed", node_id)
        return True

    def heartbeat(self, node_id: str) -> bool:
        with self._state_lock:
            node = self._nodes.get(node_id)
            if not node:
                return False
            node.last_heartbeat = time.time()
            node.status = NodeStatus.HEALTHY
        return True

    def elect_leader(self) -> str | None:
        """Elect a leader.

        Redis mode: attempt to acquire the distributed leader lease.
        Memory mode: deterministic min(node_id) over healthy nodes.
        """
        with self._state_lock:
            if self._redis_mode:
                return self._elect_leader_redis()
            return self._elect_leader_memory()

    def _elect_leader_memory(self) -> str | None:
        # 调用方已持 _state_lock（RLock 可重入）
        now = time.time()
        healthy = [
            n for n in self._nodes.values()
            if n.status == NodeStatus.HEALTHY and (now - n.last_heartbeat) < self._config.failover_timeout_s
        ]
        if not healthy:
            logger.error("[ha] No healthy nodes available for leader election")
            return None
        leader = min(healthy, key=lambda n: n.node_id)
        for n in self._nodes.values():
            n.role = NodeRole.FOLLOWER
        leader.role = NodeRole.LEADER
        self._leader_id = leader.node_id
        logger.info("[ha] Elected leader=%s", leader.node_id)
        return leader.node_id

    def _elect_leader_redis(self) -> str | None:
        # 调用方已持 _state_lock（RLock 可重入）；但 Redis 锁操作本身
        # 不需要在 _state_lock 内执行（它是跨进程锁，与本地的 _state_lock
        # 职责不同）。为保持向后兼容与最小改动，这里仍在 _state_lock 下
        # 调用 _ensure_lock / _acquire_leadership，后者会进一步修改 _nodes。
        lock = self._ensure_lock()
        if lock is None:
            # Fell back to memory mode (Redis unavailable)
            return self._elect_leader_memory()
        if self._acquire_leadership(lock):
            return self._leader_id
        return None

    def _acquire_leadership(self, lock: Any) -> bool:
        """Attempt to acquire the distributed leader lease (private)."""
        # 调用方已持 _state_lock（RLock 可重入）
        if lock.acquire(blocking=False):
            self._leader_id = self._node_id
            self._fencing_token = lock.fencing_token
            # Track self in node registry
            if self._node_id not in self._nodes:
                # register_node 也会获取 _state_lock，但 RLock 可重入
                # 不过为了避免嵌套，这里直接写 _nodes
                self._nodes[self._node_id] = ClusterNode(
                    node_id=self._node_id,
                    address="self",
                    last_heartbeat=time.time(),
                )
                logger.info("[ha] Registered node=%s address=%s", self._node_id, "self")
            for n in self._nodes.values():
                n.role = NodeRole.FOLLOWER
            self._nodes[self._node_id].role = NodeRole.LEADER
            logger.info(
                "[ha] Acquired leadership node=%s fencing_token=%s",
                self._node_id, self._fencing_token,
            )
            return True
        return False

    def renew_leadership(self) -> bool:
        """Renew the leader lease (heartbeat). Only valid if currently leader."""
        with self._state_lock:
            if not self._redis_mode or not self._leader_id:
                return False
            if self._lock is None:
                return False
        # Redis 锁刷新在 _state_lock 外执行，避免长时间持锁
        refreshed = self._lock.refresh()
        if refreshed:
            logger.debug("[ha] Renewed leadership node=%s", self._node_id)
        return refreshed  # type: ignore

    def release_leadership(self) -> bool:
        """Release the leader lease (graceful shutdown)."""
        with self._state_lock:
            if not self._leader_id:
                return False
            redis_lock = self._lock if (self._redis_mode and self._lock is not None) else None
            leader_id = self._leader_id
            # 清理本地状态
            if leader_id in self._nodes:
                self._nodes[leader_id].role = NodeRole.FOLLOWER
            self._leader_id = ""
            self._fencing_token = 0
        # Redis 锁释放在 _state_lock 外执行
        released = redis_lock.release() if redis_lock is not None else True
        logger.info("[ha] Released leadership")
        return released

    def check_health(self) -> dict[str, Any]:
        with self._state_lock:
            now = time.time()
            healthy = 0
            degraded = 0
            unreachable = 0
            # 迭代 _nodes.values() 时持锁，避免
            # RuntimeError: dictionary changed size during iteration
            for node in self._nodes.values():
                elapsed = now - node.last_heartbeat
                if elapsed > self._config.failover_timeout_s:
                    node.status = NodeStatus.UNREACHABLE
                    unreachable += 1
                elif elapsed > self._config.heartbeat_interval_s * 2:
                    node.status = NodeStatus.DEGRADED
                    degraded += 1
                else:
                    node.status = NodeStatus.HEALTHY
                    healthy += 1
            needs_failover = False
            if self._config.auto_failover and self._leader_id:
                leader_node = self._nodes.get(
                    self._leader_id, ClusterNode(node_id="", address="")
                )
                if leader_node.status != NodeStatus.HEALTHY:
                    needs_failover = True
            return {
                "total_nodes": len(self._nodes),
                "healthy": healthy,
                "degraded": degraded,
                "unreachable": unreachable,
                "leader_id": self._leader_id,
                "needs_failover": needs_failover,
                "fencing_token": self._fencing_token,
                "redis_mode": self._redis_mode,
            }

    def list_nodes(self) -> list[ClusterNode]:
        with self._state_lock:
            return list(self._nodes.values())

    # ── Phase 3.4.4: automatic failover ────────────────────────────

    def start_health_monitor(self) -> None:
        """Start the background health monitoring thread."""
        with self._state_lock:
            if self._monitor_thread is not None and self._monitor_thread.is_alive():
                logger.warning("[ha] Health monitor already running")
                return
            self._monitor_stop.clear()
            self._monitor_thread = threading.Thread(
                target=self._health_check_loop,
                name="maop-ha-monitor",
                daemon=True,
            )
            self._monitor_thread.start()
        logger.info(
            "[ha] Health monitor started (interval=%ss)",
            self._config.heartbeat_interval_s,
        )

    def stop_health_monitor(self, timeout: float = 5.0) -> None:
        """Stop the background health monitoring thread."""
        with self._state_lock:
            if self._monitor_thread is None:
                return
            thread = self._monitor_thread
            self._monitor_stop.set()
        # join 在 _state_lock 外执行，避免持锁等待线程退出（死锁风险）
        thread.join(timeout=timeout)
        with self._state_lock:
            self._monitor_thread = None
        logger.info("[ha] Health monitor stopped")

    def _health_check_loop(self) -> None:
        """Background loop: renew leadership or attempt failover."""
        interval = self._config.heartbeat_interval_s
        while not self._monitor_stop.is_set():
            try:
                with self._state_lock:
                    redis_mode = self._redis_mode
                if redis_mode:
                    self._health_check_redis()
                else:
                    self._health_check_memory()
            except Exception as exc:
                logger.error("[ha] Health check error: %s", exc)
            # Wait for interval or stop signal
            self._monitor_stop.wait(interval)

    def _health_check_memory(self) -> None:
        """Memory mode health check: update node statuses."""
        self.check_health()

    def _health_check_redis(self) -> None:
        """Redis mode health check: renew lease or attempt election."""
        with self._state_lock:
            is_leader = self._leader_id == self._node_id
            has_leader = bool(self._leader_id)
            auto_failover = self._config.auto_failover
        if is_leader:
            # We are leader: renew the lease
            if not self.renew_leadership():
                logger.warning("[ha] Lost leadership (lease renewal failed)")
                with self._state_lock:
                    self._leader_id = ""
                    self._fencing_token = 0
        else:
            # We are follower: try to acquire leadership if no leader
            if not has_leader or auto_failover:
                self.elect_leader()
        # Update node statuses
        self.check_health()
