"""Quota middleware path-mapping tests (P0 #10 rule-shadowing fix).

The ``concurrent_tasks`` rule must match BEFORE the wider ``api_calls``
rule, otherwise ``/api/agents/{id}/(run|execute|invoke)`` is always
counted as ``api_calls`` and the concurrency quota never applies.
"""
from __future__ import annotations

import pytest

from maop.enterprise.quota_middleware import (
    _DEFAULT_PATH_PATTERNS,
    QuotaMiddleware,
)


def _middleware() -> QuotaMiddleware:
    # app / quota_manager are irrelevant for pure path mapping
    return QuotaMiddleware(lambda scope, receive, send: None, quota_manager=object())


def test_concurrent_tasks_rule_is_first():
    # Ordering is the fix: first-match-wins means the specific rule must
    # precede the general one.
    assert _DEFAULT_PATH_PATTERNS[0][1] == "concurrent_tasks"


@pytest.mark.parametrize(
    "path",
    [
        "/api/agents/a1/run",
        "/api/agents/abc/execute",
        "/api/agents/x-y-z/invoke",
    ],
)
def test_agent_run_paths_map_to_concurrent_tasks(path):
    assert _middleware()._match_resource(path) == "concurrent_tasks"


@pytest.mark.parametrize(
    "path",
    [
        "/api/agents/a1/chat",
        "/api/agents/a1/complete",
    ],
)
def test_agent_chat_paths_map_to_api_calls(path):
    assert _middleware()._match_resource(path) == "api_calls"


def test_other_mappings_unchanged():
    mw = _middleware()
    assert mw._match_resource("/api/agents/register") == "agents"
    assert mw._match_resource("/api/agents/create") == "agents"
    assert mw._match_resource("/api/chat/send") == "api_calls"
    assert mw._match_resource("/api/control/run") == "api_calls"
    assert mw._match_resource("/api/memory/write") == "storage_mb"
    assert mw._match_resource("/api/data/upload") == "storage_mb"


def test_unmapped_path_returns_none():
    assert _middleware()._match_resource("/api/unknown") is None
    assert _middleware()._match_resource("/api/agents/a1/status") is None
