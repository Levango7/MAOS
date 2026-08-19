"""MAOP Enterprise Extension Package.

授权模型（2026-08-11 防破解加固):
  - 本包随 ``maop`` 主包一同发布（单发行 wheel),不再作为独立 wheel.
  - 包被 importable **不等于** enterprise 激活——必须提供有效 license key.
  - 真正的 edition 决策完全在 :func:`maop.config.edition.detect_edition`,
    它会调用 ``maop.enterprise.license.LicenseValidator`` 验证
    ``MAOP_LICENSE_KEY`` 或 ``data/license.key``.
  - 原"importable = enterprise"的 honor-system 是公开绕过路径,已移除.

因此本模块的 import 副作用**不再调用** ``set_edition(ENTERPRISE)``,改为
触发一次 ``detect_edition()``（内部会走 license 校验):
  - license 有效   → ENTERPRISE
  - license 缺失/无效 → 静默保持 PERSONAL

Submodules:
  - rbac.py          Role-Based Access Control
  - tenant.py        Multi-tenant isolation
  - audit.py         Enterprise audit logging
  - sso.py           SSO / SAML / OIDC integration
  - tls_auto.py      TLS auto-configuration
  - container.py     Docker/K8s orchestration
  - ha.py            High availability

Backend modules:
  - core/backends_pg.py      PostgreSQL storage (implemented)
  - core/backends_redis.py   Redis cache/queue/lock (implemented, Phase 3.4)
  - core/backends_vault.py   HashiCorp Vault secrets (implemented, Phase 3.3)
  - core/backends_rabbitmq.py RabbitMQ queue (implemented; requires optional pika)
  - core/backends_distributed.py etcd/Consul KV (implemented; requires optional etcd3)

Note: ``FeatureFlag.RABBITMQ`` and ``FeatureFlag.ETCD`` are intentionally
excluded from ``_ENTERPRISE_FEATURES`` in ``config/edition.py`` because
their dependencies (pika / etcd3) are optional extras, not hard
requirements.  The backend modules ARE implemented; enable them via
``MAOP_QUEUE_BACKEND=rabbitmq`` / ``MAOP_KV_BACKEND=etcd``.  See the
docstring of ``config/edition.py`` for the OPTIONAL backends policy.
"""

from __future__ import annotations

import logging

from maop.config.edition import Edition, get_edition

logger = logging.getLogger(__name__)

_edition = get_edition()
if _edition is Edition.ENTERPRISE:
    logger.info("[enterprise] MAOP Enterprise edition activated (license valid).")
else:
    logger.debug(
        "[enterprise] maop.enterprise importable but no valid license — "
        "running as personal edition. Set MAOP_LICENSE_KEY to activate."
    )

__all__: list[str] = [
    "audit",
    "container",
    "ha",
    "n8n",
    "rbac",
    "sso",
    "tenant",
    "tls_auto",
]
