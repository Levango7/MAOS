"""MAOP Enterprise Quota Middleware — FastAPI 中间件,关键 API 请求前检查配额.

设计原则:
  1. **fail-open** — 任何检查异常(无 tenant_id/无配额/DB 错误)均放行,避免
     配额子系统故障导致整个平台不可用.
  2. **仅检查不消费** — 中间件只调用 :meth:`QuotaManager.check_quota`,
     不调用 :meth:`QuotaManager.consume`. 实际消费由业务层显式调用
     (避免中间件与业务层双重计数).
  3. **路径映射** — 通过 ``path_patterns`` 将 URL 映射到资源标识符
     (e.g. ``/api/agents/*`` → ``api_calls``).
  4. **429 Too Many Requests** — 硬限制触发时返回 429 + ErrorSchema 风格体.

启用方式(在 ``server.py`` 中)::

    from maop.enterprise.quota_middleware import QuotaMiddleware
    app.add_middleware(QuotaMiddleware, quota_manager=qm)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any, cast

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from maop.config.edition import FeatureFlag, has_feature

logger = logging.getLogger(__name__)

# ── 默认路径 → 资源映射 ────────────────────────────────────────────

#: 每条规则: (compiled_pattern, resource_name). 匹配按顺序,首条命中即用.
#: 资源名与 :mod:`maop.enterprise.quota` 的 KNOWN_RESOURCES 对齐.
_DEFAULT_PATH_PATTERNS: list[tuple[str, str]] = [
    # 智能体执行/调用 → api_calls
    (r"^/api/agents/[^/]+/(run|execute|invoke|chat|complete)$", "api_calls"),
    (r"^/api/control/(run|execute|invoke)$", "api_calls"),
    (r"^/api/chat/(send|message)$", "api_calls"),
    # 任务并发 → concurrent_tasks
    (r"^/api/agents/[^/]+/(run|execute|invoke)$", "concurrent_tasks"),
    # 智能体注册 → agents
    (r"^/api/agents/(register|create)$", "agents"),
    # 数据写入 → storage_mb (粗粒度,按请求计)
    (r"^/api/memory/(write|save|store)$", "storage_mb"),
    (r"^/api/data/(write|save|upload)$", "storage_mb"),
]

# 公开路径(跳过配额检查)
_DEFAULT_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/", "/api/health", "/api/prometheus",
    "/api/docs", "/openapi.json",
    "/api/auth/login", "/api/auth/logout", "/api/auth/refresh", "/api/auth/status",
    "/api/info/edition", "/api/info/config",
    # 配额管理自身不走配额检查(避免自锁)
    "/api/quotas",
})


class QuotaMiddleware(BaseHTTPMiddleware):
    """FastAPI 中间件: 关键 API 请求前检查租户配额.

    Parameters
    ----------
    app : ASGIApp
        FastAPI 应用.
    quota_manager : QuotaManager | None
        配额管理器实例. ``None`` 时中间件变为 no-op(用于 Personal 版).
    path_patterns : list[tuple[str, str]] | None
        自定义 (regex_pattern, resource) 映射. ``None`` 使用默认.
    public_paths : frozenset[str] | None
        跳过检查的路径前缀/精确路径. ``None`` 使用默认.
    enabled : bool
        总开关. ``False`` 时中间件 no-op.
    """

    def __init__(
        self,
        app: Any,
        *,
        quota_manager: Any = None,
        path_patterns: list[tuple[str, str]] | None = None,
        public_paths: frozenset[str] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)
        # quota_manager=None 时惰性加载(首次请求时从 routers.quotas 获取),
        # 这样 server.py 可在 Auth 之前无条件注册本中间件,Personal 版
        # 通过 has_feature 检查自动 no-op.
        self._quota_manager = quota_manager
        self._lazy_loaded = quota_manager is None
        self._enabled = enabled
        patterns = path_patterns if path_patterns is not None else _DEFAULT_PATH_PATTERNS
        # 预编译正则
        self._compiled: list[tuple[re.Pattern[str], str]] = [
            (re.compile(p), r) for p, r in patterns
        ]
        self._public_paths = public_paths if public_paths is not None else _DEFAULT_PUBLIC_PATHS

    def _resolve_manager(self) -> Any:
        """惰性获取 QuotaManager 单例. 失败返回 None(触发 fail-open)."""
        if self._quota_manager is not None:
            return self._quota_manager
        if not self._lazy_loaded:
            return None
        try:
            from maop.dashboard.routers.quotas import _get_manager
            self._quota_manager = _get_manager()
            self._lazy_loaded = False
            return self._quota_manager
        except Exception as exc:
            logger.debug("[quota-mw] lazy load failed: %s", exc)
            return None

    async def dispatch(
        self, request: Request, call_next: Callable,
    ) -> Response:
        if not self._enabled:
            return cast(Response, await call_next(request))

        # Personal 版无 TENANT_ISOLATION 特性 → no-op
        if not has_feature(FeatureFlag.TENANT_ISOLATION):
            return cast(Response, await call_next(request))

        # 惰性获取 QuotaManager(失败 fail-open)
        qm = self._resolve_manager()
        if qm is None:
            return cast(Response, await call_next(request))

        path = request.url.path

        # 跳过公开路径
        if self._is_public(path):
            return cast(Response, await call_next(request))

        # 跳过非关键方法(只检查写操作)
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return cast(Response, await call_next(request))

        # 映射路径 → 资源
        resource = self._match_resource(path)
        if resource is None:
            return cast(Response, await call_next(request))

        # 获取 tenant_id (fail-open: 无 tenant_id 放行)
        tenant_id = self._extract_tenant_id(request)
        if not tenant_id:
            return cast(Response, await call_next(request))

        # 检查配额 (fail-open: 异常放行)
        try:
            result = qm.check_quota(tenant_id, resource, amount=1)
        except Exception as exc:
            logger.warning(
                "[quota-mw] check failed (fail-open) tenant=%s resource=%s path=%s: %s",
                tenant_id, resource, path, exc,
            )
            return cast(Response, await call_next(request))

        if not result.allowed:
            logger.info(
                "[quota-mw] DENY tenant=%s resource=%s path=%s reason=%s",
                tenant_id, resource, path, result.reason,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "status": "error",
                    "error": "quota exceeded",
                    "code": "QUOTA_EXCEEDED",
                    "detail": result.reason,
                    "resource": resource,
                    "tenant_id": tenant_id,
                },
                headers={
                    # 标准 Retry-After 提示客户端退避
                    "Retry-After": "60",
                    "X-Quota-Resource": resource,
                    "X-Quota-Tenant": tenant_id,
                },
            )

        # 放行(可能附带软限制警告头)
        response = cast(Response, await call_next(request))
        if result.warning:
            response.headers["X-Quota-Warning"] = result.warning
        if result.alert_id:
            response.headers["X-Quota-Alert-Id"] = result.alert_id
        return response

    # ── 内部辅助 ──────────────────────────────────────────────────

    def _is_public(self, path: str) -> bool:
        """判断是否公开路径. 精确匹配或前缀匹配."""
        for pub in self._public_paths:
            if path == pub or path.startswith(pub + "/"):
                return True
        return False

    def _match_resource(self, path: str) -> str | None:
        """将 URL path 映射到资源标识符. 首条命中返回."""
        for pattern, resource in self._compiled:
            if pattern.match(path):
                return resource
        return None

    @staticmethod
    def _extract_tenant_id(request: Request) -> str:
        """从请求中提取 tenant_id.

        优先级:
          1. ``request.state.tenant_id`` (AuthMiddleware 注入)
          2. ``request.state.auth_tenant_id`` (备选)
          3. ``""`` (无 → fail-open 放行)
        """
        tid = getattr(request.state, "tenant_id", None)
        if tid and isinstance(tid, str):
            return tid
        tid = getattr(request.state, "auth_tenant_id", None)
        if tid and isinstance(tid, str):
            return tid
        return ""