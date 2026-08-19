"""MAOP Enterprise License CRL（Certificate Revocation List）检查模块。

支持 HTTP 拉取 CRL + 本地缓存 + 离线降级。

CRL JSON 格式:
    {
      "version": 1,
      "updated_at": "2026-07-27T10:00:00Z",
      "expires_at": "2026-07-27T11:00:00Z",
      "revoked": [
        {
          "customer": "Acme Corp",
          "revoked_at": "2026-07-25T14:30:00Z",
          "reason": "non-payment"
        }
      ]
    }

环境变量:
    MAOP_CRL_URL            CRL 服务 URL（设置后启用 CRL 检查）
    MAOP_CRL_CACHE_TTL_S    缓存有效期秒数（默认 3600）
    MAOP_CRL_STRICT         严格模式（1=无 CRL 时拒绝 license，0=允许，默认 0）
    MAOP_CRL_MAX_CACHE_AGE_S 缓存最大过期秒数（默认 604800=7天，超过后即使 lax 模式也警告）

离线降级策略:
    - 优先使用新鲜缓存（未过 TTL）
    - 缓存过期或不存在时尝试 HTTP 拉取
    - 拉取失败时降级使用过期缓存
    - 无任何缓存时：
        * 严格模式（MAOP_CRL_STRICT=1）：抛 CRLError，拒绝 license
        * 宽松模式（默认）：允许 license，仅依赖签名+过期检查
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from maop.enterprise.license import LicenseError

if TYPE_CHECKING:
    from maop.enterprise.license import LicenseInfo

logger = logging.getLogger(__name__)

__all__ = [
    "CRLChecker",
    "CRLError",
    "LicenseRevokedError",
]

# HTTP 拉取 CRL 的超时秒数
_HTTP_TIMEOUT_S = 10.0
# 缓存最大过期秒数（7 天），超过后即使 lax 模式也记录 WARNING
_DEFAULT_MAX_CACHE_AGE_S = 86400.0 * 7.0


class CRLError(RuntimeError):
    """CRL 检查相关错误。"""


class LicenseRevokedError(LicenseError):
    """License 已被撤销。"""

    def __init__(self, customer: str, reason: str, revoked_at: str) -> None:
        self.customer = customer
        self.reason = reason
        self.revoked_at = revoked_at
        super().__init__(
            f"License for '{customer}' was revoked at {revoked_at} (reason: {reason})"
        )


class CRLChecker:
    """License 在线撤销列表检查器。

    支持 HTTP 拉取 CRL + 本地缓存 + 离线降级。
    """

    def __init__(
        self,
        crl_url: str = "",
        cache_path: Path | None = None,
        cache_ttl_s: float = 3600.0,
        strict: bool = False,
    ) -> None:
        """初始化 CRL 检查器。

        Args:
            crl_url: CRL 服务 URL（空则从 MAOP_CRL_URL 环境变量读取）
            cache_path: 本地缓存路径（默认 data/crl_cache.json）
            cache_ttl_s: 缓存有效期秒数（默认 3600）
            strict: 严格模式（无 CRL 时拒绝 license）
        """
        # crl_url: 显式参数优先，否则读环境变量
        self.crl_url: str = crl_url or os.getenv("MAOP_CRL_URL", "").strip()
        # cache_path: 默认 data/crl_cache.json
        self.cache_path: Path = (
            cache_path if cache_path is not None else Path("data/crl_cache.json")
        )
        # cache_ttl_s: 环境变量优先（便于运维调参），否则用参数
        env_ttl = os.getenv("MAOP_CRL_CACHE_TTL_S")
        if env_ttl:
            try:
                self.cache_ttl_s: float = float(env_ttl)
            except ValueError:
                logger.warning(
                    "[crl] Invalid MAOP_CRL_CACHE_TTL_S=%r, using default", env_ttl
                )
                self.cache_ttl_s = cache_ttl_s
        else:
            self.cache_ttl_s = cache_ttl_s
        # strict: 环境变量优先，否则用参数
        env_strict = os.getenv("MAOP_CRL_STRICT")
        if env_strict is not None:
            self.strict: bool = env_strict.strip() == "1"
        else:
            self.strict = strict

    def is_revoked(self, customer: str) -> tuple[bool, str]:
        """检查 license 是否被撤销。

        Returns:
            (is_revoked, reason): 如果被撤销返回 (True, reason)，否则 (False, "")

        Raises:
            CRLError: 严格模式下无法获取 CRL 时抛出
        """
        entry = self._find_revocation(customer)
        if entry is not None:
            return (True, entry.get("reason", ""))
        return (False, "")

    def _find_revocation(self, customer: str) -> dict | None:
        """查找 customer 的撤销条目。找不到返回 None。

        严格模式下无法获取 CRL 时抛 CRLError。
        """
        crl = self._get_crl()
        if crl is None:
            # 无 CRL 可用（无新鲜缓存、拉取失败、无过期缓存）
            if self.strict:
                raise CRLError(
                    "Unable to obtain CRL (fetch failed and no cache available) "
                    "while strict mode is enabled"
                )
            # 宽松模式：允许
            return None
        for entry in crl.get("revoked", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("customer") == customer:
                return entry
        return None

    def _get_crl(self) -> dict | None:
        """获取 CRL：优先新鲜缓存 → HTTP 拉取 → 过期缓存降级。"""
        # 1. 尝试加载新鲜缓存（未过 TTL）
        crl = self._load_cached_crl()
        if crl is not None:
            return crl
        # 2. 尝试从远程拉取
        fetched = self._fetch_crl()
        if fetched is not None:
            return fetched
        # 3. 离线降级：使用过期缓存
        return self._load_cached_crl_raw()

    def _fetch_crl(self) -> dict | None:
        """从远程拉取 CRL，更新本地缓存。失败返回 None。"""
        if not self.crl_url:
            return None
        try:
            req = urllib.request.Request(
                self.crl_url,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
                status = getattr(resp, "status", 200)
                if status != 200:
                    logger.warning("[crl] CRL service returned HTTP %d", status)
                    return None
                raw = resp.read()
            data = json.loads(raw.decode("utf-8"))
            if not self._validate_crl(data):
                logger.warning("[crl] Fetched CRL has invalid structure")
                return None
            self._save_cache(data)
            revoked_count = len(data.get("revoked", []))
            logger.debug(
                "[crl] Fetched CRL from %s (%d revoked entries)",
                self.crl_url,
                revoked_count,
            )
            return data  # type: ignore
        except Exception as exc:
            logger.warning("[crl] Failed to fetch CRL from %s: %s", self.crl_url, exc)
            return None

    def _load_cached_crl(self) -> dict | None:
        """加载本地缓存的 CRL。过期或不存在返回 None。"""
        if not self.cache_path.exists():
            return None
        try:
            mtime = self.cache_path.stat().st_mtime
            # 负 age（mtime 超前/Windows os.stat 时间精度进位）→ 视为 0：
            # 缓存刚写入 = 新鲜。此前 `age < 0` 直接判过期会误伤 TTL>0 的
            # 正常缓存（test_crl_cache_prevents_refetch：TTL=300 应读缓存却
            # 重拉）。max(0, ...) 下：TTL=0 → age 0>=0 过期重拉 ✓；
            # TTL=300 → age 0<300 新鲜用缓存 ✓。
            age = max(0.0, time.time() - mtime)
            if age >= self.cache_ttl_s:
                return None  # 缓存已过期
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if not self._validate_crl(data):
                return None
            return data  # type: ignore
        except Exception as exc:
            logger.debug("[crl] Failed to load cached CRL: %s", exc)
            return None

    def _load_cached_crl_raw(self) -> dict | None:
        """加载本地缓存的 CRL（忽略 TTL，用于离线降级）。

        如果缓存超过最大过期时间（默认 7 天），记录 WARNING。
        """
        if not self.cache_path.exists():
            return None
        try:
            mtime = self.cache_path.stat().st_mtime
            age = time.time() - mtime
            max_age_s = float(
                os.getenv("MAOP_CRL_MAX_CACHE_AGE_S", str(_DEFAULT_MAX_CACHE_AGE_S))
            )
            if age > max_age_s:
                logger.warning(
                    "[crl] Cache is stale (>%.0f days). Revocation status may be outdated.",
                    max_age_s / 86400.0,
                )
                if self.strict:
                    raise CRLError(
                        f"CRL cache expired (>{max_age_s / 86400.0:.0f} days) "
                        "and CRL service unreachable while strict mode is enabled"
                    )
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if not self._validate_crl(data):
                return None
            return data  # type: ignore
        except CRLError:
            raise
        except Exception as exc:
            logger.debug("[crl] Failed to load cached CRL (raw): %s", exc)
            return None

    def _save_cache(self, crl_data: dict) -> None:
        """保存 CRL 到本地缓存（原子写入：先写临时文件再 rename）。"""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.cache_path.parent / (self.cache_path.name + ".tmp")
        try:
            tmp_path.write_text(
                json.dumps(crl_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            # 原子 rename（同目录下，保证在同一文件系统）
            os.replace(str(tmp_path), str(self.cache_path))
        except Exception as exc:
            logger.warning("[crl] Failed to save CRL cache: %s", exc)
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                logger.debug('swallowed exception', exc_info=True)

    @staticmethod
    def _validate_crl(data: object) -> bool:
        """验证 CRL 结构是否合法（必须包含 revoked 列表）。"""
        if not isinstance(data, dict):
            return False
        revoked = data.get("revoked")
        return isinstance(revoked, list)

    def check_license(self, info: LicenseInfo) -> None:
        """检查 license 是否被撤销（集成点）。

        Args:
            info: 已验证签名的 LicenseInfo

        Raises:
            LicenseRevokedError: license 被撤销
            CRLError: 严格模式下无法获取 CRL
        """
        entry = self._find_revocation(info.customer)
        if entry is not None:
            raise LicenseRevokedError(
                info.customer,
                entry.get("reason", ""),
                entry.get("revoked_at", ""),
            )
