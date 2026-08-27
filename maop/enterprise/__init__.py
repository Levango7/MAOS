"""MAOP Enterprise Extension Package.

授权模型（2026-08-11 防破解加固):
  - 本包作为独立的 ``maop-enterprise`` wheel 发布（双 wheel 模式,ADR-018).
  - 主包 ``maop`` 通过延迟导入 ``maop.enterprise.*`` 使用企业功能,未安装时优雅降级.
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
import os

from maop.config.edition import Edition, get_edition, record_degradation

logger = logging.getLogger(__name__)

_edition = get_edition()
if _edition is Edition.ENTERPRISE:
    logger.info("[enterprise] MAOP Enterprise edition activated (license valid).")
else:
    logger.debug(
        "[enterprise] maop.enterprise importable but no valid license — "
        "running as personal edition. Set MAOP_LICENSE_KEY to activate."
    )


def _run_integrity_check() -> None:
    """P0 #7: 启动时执行企业模块完整性校验（此前 verify_module_integrity
    是死代码，从无任何调用点）。

    行为：
      - ``MAOP_SKIP_INTEGRITY=1`` → 跳过（测试/开发逃生舱）。
      - manifest 缺失：开发环境静默跳过（尚未签名属正常）；生产环境
        （``MAOP_ENV=production``）视为篡改嫌疑，抛 ModuleTamperError 阻断。
      - manifest 存在但校验失败（签名错/文件被改）→ 记录降级 + 告警；
        生产环境由 verify_module_integrity 的 strict 模式直接抛异常。
    """
    from maop.enterprise.license import (
        ModuleTamperError,
        verify_module_integrity,
    )

    try:
        ok, reason = verify_module_integrity()
    except ModuleTamperError:
        record_degradation(
            "integrity", "enterprise", "blocked", reason="module_tamper_detected"
        )
        raise
    if ok:
        if reason != "skipped":
            logger.debug("[enterprise] module integrity verified: %s", reason)
        return
    if "manifest not found" in reason:
        # 开发/CI 未签名场景：不记降级，仅提示
        logger.info(
            "[enterprise] integrity manifest not present — skipping module "
            "verification (run scripts/sign_enterprise_modules.py to sign)"
        )
        return
    record_degradation(
        "integrity", "enterprise", "personal", reason=f"integrity_check_failed:{reason}"
    )
    logger.warning("[enterprise] module integrity check failed: %s", reason)


# 测试逃生舱：显式跳过时不执行任何检查逻辑
if os.getenv("MAOP_SKIP_INTEGRITY", "").strip().lower() not in ("1", "true", "yes"):
    _run_integrity_check()

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
