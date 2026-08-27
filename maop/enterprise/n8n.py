"""MAOP Enterprise n8n Integration.

Provides bidirectional integration with n8n workflow automation:
  - Outbound: MAOP agent triggers n8n workflow during execution
  - Inbound: n8n webhook calls MAOP /api/delegate for LLM processing

n8n is positioned as the "external trigger + SaaS integration layer":
  - Listens to 400+ SaaS events (GitHub/Slack/Jira/Email/etc.)
  - Calls MAOP for intelligent LLM processing at decision points
  - Distributes MAOP's results to external systems

This module is gated behind FeatureFlag.N8N_INTEGRATION (Enterprise only).
Personal edition cannot use n8n integration.

Architecture:
  ┌──────────────┐    webhook    ┌──────────────┐
  │  n8n         │ ────────────> │  MAOP        │
  │  (workflows) │ <───────────  │  (LLM brain) │
  └──────────────┘  HTTP trigger  └──────────────┘

Usage:
    from maop.enterprise.n8n import N8nClient, require_n8n_feature

    require_n8n_feature()  # raises FeatureNotAvailable in personal edition

    client = N8nClient(base_url="http://localhost:5678", api_key="...")
    execution = client.trigger_workflow("workflow-123", {"input": "data"})
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator
from typing_extensions import Self

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)

# 模块级标志：N8N_WEBHOOK_SECRET 未配置时仅记录一次警告，避免刷屏
_webhook_secret_warned: bool = False

__all__ = [
    "N8nClient",
    "N8nIntegrationError",
    "N8nWebhookPayload",
    "N8nWorkflowExecution",
    "require_n8n_feature",
]


class N8nIntegrationError(Exception):
    """Base exception for n8n integration errors."""


class N8nWorkflowExecution(BaseModel):
    """Represents an n8n workflow execution."""

    execution_id: str = Field(description="n8n execution ID")
    workflow_id: str = Field(description="n8n workflow ID")
    status: str = Field(description="Execution status: running|success|error|crashed")
    started_at: datetime = Field(description="When execution started")
    finished_at: datetime | None = Field(default=None, description="When execution finished")
    data: dict[str, Any] | None = Field(default=None, description="Execution output data")
    error: str | None = Field(default=None, description="Error message if failed")


def verify_webhook_signature(
    payload_body: bytes, signature_header: str | None, secret: str | None
) -> bool:
    """校验 n8n webhook 的 HMAC-SHA256 签名。

    用恒定时间比较（``hmac.compare_digest``）防止时序攻击。
    secret 为空或 signature_header 为空时返回 False。
    """
    if not secret or not signature_header:
        return False
    expected = hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def is_safe_callback_url(url: str) -> bool:
    """检查 callback_url 是否安全（拒绝私网/保留 IP，防 SSRF）。

    允许 http/https 协议；主机名（IP 或域名）必须解析到公网地址。
    私网（10.x/172.16-31.x/192.168.x）、环回（127.x/::1）、链路本地
    （169.254.x，含云元数据端点）、组播、保留、未指定地址全部拒绝。
    DNS 解析失败或任何异常均返回 False。
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False

    def _ip_unsafe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    # 直接 IP 主机
    try:
        return not _ip_unsafe(ipaddress.ip_address(host))
    except ValueError:
        pass

    # 域名：解析所有 A/AAAA 记录，任一为私网即拒绝
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            if _ip_unsafe(ipaddress.ip_address(addr)):
                return False
        except ValueError:
            continue
    return True


class N8nWebhookPayload(BaseModel):
    """Payload received from n8n webhook."""

    workflow_id: str = Field(description="n8n workflow ID that triggered this webhook")
    execution_id: str = Field(description="n8n execution ID")
    event: str = Field(description="Event type (e.g., 'github.pr.opened', 'slack.message')")
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload data")
    callback_url: str | None = Field(default=None, description="URL to POST results back to")

    @field_validator("callback_url")
    @classmethod
    def validate_callback_url(cls, v: str | None) -> str | None:
        """SSRF 防护：callback_url 必须是公网 http/https URL。"""
        if v is not None and v != "" and not is_safe_callback_url(v):
            raise ValueError("callback_url must be public https/http URL")
        return v


def require_n8n_feature() -> None:
    """Assert that n8n integration is available.

    Raises FeatureNotAvailable if:
      - Running in Personal edition
      - N8N_INTEGRATION feature flag is not enabled
    """
    require_feature(FeatureFlag.N8N_INTEGRATION)


def _parse_iso(dt_str: str) -> datetime:
    """Parse ISO 8601 datetime, tolerating a trailing Z suffix.
    Python < 3.11 datetime.fromisoformat rejects Z; n8n returns Z timestamps.
    """
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    return datetime.fromisoformat(dt_str)


class N8nClient:
    """HTTP client for n8n REST API.

    n8n API docs: https://docs.n8n.io/api/

    Used for outbound integration: MAOP triggers n8n workflows
    during agent execution (e.g., "after code review, create Jira ticket").
    """

    def __init__(
        self,
        base_url: str = "http://localhost:5678",
        api_key: str = "",
        api_version: str = "v1",
        timeout_s: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._api_version = api_version
        self._timeout_s = timeout_s
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["X-N8N-API-KEY"] = self._api_key
            self._client = httpx.Client(
                base_url=f"{self._base_url}/api/{self._api_version}",
                headers=headers,
                timeout=self._timeout_s,
            )
        return self._client

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def trigger_workflow(
        self,
        workflow_id: str,
        data: dict[str, Any] | None = None,
        wait_for_completion: bool = False,
        webhook_path: str = "",
        use_test_webhook: bool = False,
    ) -> N8nWorkflowExecution:
        """Trigger an n8n workflow via its Webhook trigger node.

        P1 #21 fix: 旧实现调用 ``POST /api/v1/workflows/{id}/execute``，
        该端点在 n8n API 中不存在（恒 404）。n8n 的外部触发机制是
        工作流内的 Webhook trigger node：

          - 生产（已激活工作流）: ``POST {base_url}/webhook/{path}``
          - 编辑器测试: ``POST {base_url}/webhook-test/{path}``

        webhook path 在 Webhook node 上配置；未指定时用 workflow_id
        作为 path（n8n 默认值）。注意 webhook URL 不走 ``/api/v1``
        前缀；鉴权跟随 Webhook node 配置（如 Header Auth），api_key
        仍会以 ``X-N8N-API-KEY`` 头附带。

        Parameters
        ----------
        workflow_id : str
            The n8n workflow ID to trigger（同时作为默认 webhook path）。
        data : dict, optional
            Input data POSTed as JSON body to the webhook trigger node.
        wait_for_completion : bool
            保留参数（签名兼容）。实际响应时机由 Webhook node 的
            "Respond" 模式决定：设为 "When workflow finishes" 时响应
            含执行结果；"Immediately" 时立即返回、本方法 status="running"。
        webhook_path : str
            覆盖 webhook path（工作流 Webhook node 自定义 path 时使用）。
        use_test_webhook : bool
            True 时走 ``/webhook-test/``（仅编辑器测试运行有效）。

        Returns
        -------
        N8nWorkflowExecution
            Execution info.
        """
        require_n8n_feature()

        path = webhook_path or workflow_id
        segment = "webhook-test" if use_test_webhook else "webhook"
        url = f"{self._base_url}/{segment}/{path}"

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-N8N-API-KEY"] = self._api_key

        try:
            resp = httpx.post(url, json=data or {}, headers=headers, timeout=self._timeout_s)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise N8nIntegrationError(
                f"n8n webhook returned {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise N8nIntegrationError(
                f"Failed to connect to n8n webhook at {url}: {exc}"
            ) from exc

        # 响应体取决于 Webhook node 的 respond 模式；容忍非 JSON 响应
        result: dict[str, Any] = {}
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                result = parsed
        except ValueError:
            pass

        now = datetime.now(timezone.utc)
        status = str(result.get("status") or "")
        if not status:
            # 立即响应模式：无执行状态可取 → 视为 running
            status = "success" if result else "running"
        finished = status in ("success", "error", "crashed")
        data_out = result.get("data")
        if not isinstance(data_out, dict):
            data_out = result or None
        return N8nWorkflowExecution(
            execution_id=str(result.get("executionId", "")),
            workflow_id=workflow_id,
            status=status,
            started_at=now,
            finished_at=now if finished else None,
            data=data_out,
            error=str(result["error"]) if result.get("error") else None,
        )

    def get_execution(self, execution_id: str) -> N8nWorkflowExecution:
        """Get the status of a workflow execution."""
        require_n8n_feature()

        client = self._get_client()
        try:
            resp = client.get(f"/executions/{execution_id}")
            resp.raise_for_status()
            result = resp.json()

            return N8nWorkflowExecution(
                execution_id=str(result.get("id", execution_id)),
                workflow_id=str(result.get("workflowId", "")),
                status=result.get("status", "unknown"),
                started_at=_parse_iso(result["startedAt"]) if result.get("startedAt") else datetime.now(timezone.utc),
                finished_at=_parse_iso(result["finishedAt"]) if result.get("finishedAt") else None,
                data=result.get("data"),
                error=result.get("error"),
            )
        except httpx.HTTPStatusError as exc:
            raise N8nIntegrationError(
                f"n8n API returned {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise N8nIntegrationError(f"Failed to connect to n8n: {exc}") from exc

    def list_workflows(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all workflows in n8n."""
        require_n8n_feature()

        client = self._get_client()
        try:
            resp = client.get("/workflows", params={"limit": limit})
            resp.raise_for_status()
            return resp.json().get("data", [])  # type: ignore
        except httpx.HTTPStatusError as exc:
            raise N8nIntegrationError(
                f"n8n API returned {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise N8nIntegrationError(f"Failed to connect to n8n: {exc}") from exc

    def health_check(self) -> bool:
        """Check if n8n is reachable."""
        try:
            client = self._get_client()
            resp = client.get("/workflows", params={"limit": 1})
            return resp.status_code == 200  # type: ignore
        except Exception:
            return False


def handle_n8n_webhook(
    payload: dict[str, Any],
    *,
    raw_body: bytes | None = None,
    signature: str | None = None,
) -> dict[str, Any]:
    """Process an inbound webhook from n8n.

    This function is called when n8n sends a webhook to MAOP
    (e.g., "GitHub PR opened → n8n → MAOP for code review").

    签名校验：若配置了环境变量 ``N8N_WEBHOOK_SECRET``，则必须传入
    ``raw_body`` 与 ``signature`` 且 HMAC-SHA256 匹配，否则拒绝请求。
    未配置 secret 时仅记录一次警告（向后兼容），但仍允许处理。

    The function:
      1. 校验 HMAC 签名（若已配置 secret）
      2. Validates the payload（含 callback_url SSRF 防护）
      3. Parses the event type and data
      4. Returns a response that n8n can use in subsequent nodes

    Parameters
    ----------
    payload : dict
        The JSON body received from n8n.
    raw_body : bytes, optional
        原始请求体（用于签名校验，避免 JSON 反序列化后字节不一致）。
    signature : str, optional
        请求头中的 HMAC-SHA256 签名（``X-N8N-Signature`` 或 ``X-MAOP-Signature``）。

    Returns
    -------
    dict
        Response to send back to n8n. Contains:
          - status: "accepted" | "rejected"
          - event: the parsed event type
          - data: the parsed event data
          - delegate_hint: suggested agent + task for MAOP processing
    """
    require_n8n_feature()

    # HMAC 签名校验
    secret = os.getenv("N8N_WEBHOOK_SECRET", "")
    if secret:
        if raw_body is None or not verify_webhook_signature(raw_body, signature, secret):
            logger.warning("[n8n] Webhook rejected: invalid or missing signature")
            return {"status": "rejected", "error": "Invalid or missing signature"}
    else:
        global _webhook_secret_warned
        if not _webhook_secret_warned:
            logger.warning(
                "[n8n] N8N_WEBHOOK_SECRET not set — webhook signature verification "
                "disabled. Configure N8N_WEBHOOK_SECRET for production."
            )
            _webhook_secret_warned = True

    try:
        webhook = N8nWebhookPayload(**payload)
    except Exception as exc:
        logger.warning("[n8n] Invalid webhook payload: %s", exc)
        return {"status": "rejected", "error": f"Invalid payload: {exc}"}

    # Parse event type to suggest an MAOP agent
    delegate_hint = _suggest_agent_for_event(webhook.event)

    logger.info(
        "[n8n] Webhook received: event=%s workflow=%s execution=%s",
        webhook.event, webhook.workflow_id, webhook.execution_id,
    )

    return {
        "status": "accepted",
        "event": webhook.event,
        "execution_id": webhook.execution_id,
        "workflow_id": webhook.workflow_id,
        "data": webhook.data,
        "delegate_hint": delegate_hint,
    }


def _suggest_agent_for_event(event: str) -> dict[str, str]:
    """Suggest an MAOP agent + task based on the n8n event type.

    This is a heuristic mapping. Users can override the suggested agent
    in their n8n workflow configuration.
    """
    event_lower = event.lower()

    if "github" in event_lower and ("pr" in event_lower or "pull_request" in event_lower):
        return {"agent": "claude", "task": "Review this pull request", "capability": "review"}
    if "github" in event_lower and "issue" in event_lower:
        return {"agent": "claude", "task": "Analyze this GitHub issue", "capability": "planning"}
    if "slack" in event_lower and "message" in event_lower:
        return {"agent": "claude", "task": "Analyze this Slack message", "capability": "chat"}
    if "jira" in event_lower or "ticket" in event_lower:
        return {"agent": "claude", "task": "Analyze this Jira ticket", "capability": "planning"}
    if "email" in event_lower:
        return {"agent": "claude", "task": "Analyze this email", "capability": "chat"}
    if "commit" in event_lower:
        return {"agent": "claude", "task": "Review this commit", "capability": "review"}

    return {"agent": "claude", "task": "Process this event", "capability": "chat"}
