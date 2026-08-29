"""Module integrity manifest tests (P0 #7): sign → verify → tamper detect.

Exercises the full integrity pipeline:
  - ``scripts/sign_enterprise_modules.py`` helpers (collect + sign)
  - ``maop.enterprise.license.verify_module_integrity`` (verify)

Test isolation: the manifest is written to a **tmp_path** (not the repo's
``maop/enterprise/_integrity_manifest.json``) and passed via the new
``manifest_path`` parameter of ``verify_module_integrity``. 模块文件的哈希
基准固定在 ``maop/enterprise/`` 实际目录（verify 内 ``Path(__file__).parent``），
不随 manifest 位置漂移。旧实现直接读写/删除仓库内真实 manifest 与模块
文件——在沙箱/CI 环境会被安全删除策略拦截，且测试中断会破坏仓库状态。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import maop.enterprise.license as license_mod

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTERPRISE_DIR = REPO_ROOT / "maop" / "enterprise"
SIGN_SCRIPT = REPO_ROOT / "scripts" / "sign_enterprise_modules.py"


def _load_sign_tool():
    """Load scripts/sign_enterprise_modules.py (no package __init__)."""
    spec = importlib.util.spec_from_file_location("_sign_tool", SIGN_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def integrity_env(tmp_path, monkeypatch):
    """Ephemeral Ed25519 keypair + patched public key + tmp manifest path."""
    monkeypatch.delenv("MAOP_SKIP_INTEGRITY", raising=False)
    monkeypatch.setenv("MAOP_ENV", "test")  # strict defaults to False

    private_key = Ed25519PrivateKey.generate()
    pub_path = tmp_path / "public_key.pem"
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(license_mod, "_PUBLIC_KEY_PATH", pub_path)

    manifest_path = tmp_path / "_integrity_manifest.json"
    yield private_key, _load_sign_tool(), manifest_path


def _sign_and_write(private_key, tool, manifest_path: Path) -> dict:
    files = tool.collect_module_hashes(ENTERPRISE_DIR)
    manifest = tool.build_and_sign(files, private_key, "2026-08-28T00:00:00Z")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest  # type: ignore[no-any-return]


# ── tests ───────────────────────────────────────────────────────────


def test_collect_module_hashes_covers_enterprise_package():
    tool = _load_sign_tool()
    files = tool.collect_module_hashes(ENTERPRISE_DIR)
    assert files, "no module hashes collected"
    # keys use repo-relative posix paths, values are sha256 hex
    for key, digest in files.items():
        assert key.startswith("maop/enterprise/")
        assert key.endswith(".py")
        assert len(digest) == 64
    assert "maop/enterprise/license.py" in files


def test_sign_and_verify_ok(integrity_env):
    private_key, tool, manifest_path = integrity_env
    _sign_and_write(private_key, tool, manifest_path)
    ok, reason = license_mod.verify_module_integrity(manifest_path=manifest_path)
    assert ok, reason
    assert reason == "ok"


def test_tampered_module_detected(integrity_env):
    private_key, tool, manifest_path = integrity_env
    _sign_and_write(private_key, tool, manifest_path)
    target = ENTERPRISE_DIR / "ha.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# tampered\n")
        ok, reason = license_mod.verify_module_integrity(manifest_path=manifest_path)
        assert not ok
        assert "maop/enterprise/ha.py" in reason
    finally:
        target.write_bytes(original)
    # restored → verification passes again
    ok, reason = license_mod.verify_module_integrity(manifest_path=manifest_path)
    assert ok, reason


def test_forged_manifest_signature_rejected(integrity_env):
    private_key, tool, manifest_path = integrity_env
    manifest = _sign_and_write(private_key, tool, manifest_path)
    # corrupt the signature (attacker without the private key cannot re-sign)
    sig = str(manifest["signature"])
    manifest["signature"] = ("AAAA" if not sig.startswith("AAAA") else "BBBB") + sig[4:]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    ok, reason = license_mod.verify_module_integrity(manifest_path=manifest_path)
    assert not ok
    assert "signature" in reason


def test_missing_manifest_fails(integrity_env):
    # 指向不存在的 manifest 路径 → manifest not found（无需删除真实文件，
    # 沙箱/CI 下删除仓库文件会被安全策略拦截）
    private_key, tool, manifest_path = integrity_env
    _sign_and_write(private_key, tool, manifest_path)
    missing = manifest_path.with_name("nonexistent_manifest.json")
    ok, reason = license_mod.verify_module_integrity(manifest_path=missing)
    assert not ok
    assert "manifest not found" in reason


def test_strict_mode_raises(integrity_env):
    private_key, tool, manifest_path = integrity_env
    _sign_and_write(private_key, tool, manifest_path)
    missing = manifest_path.with_name("nonexistent_manifest.json")
    with pytest.raises(license_mod.ModuleTamperError):
        license_mod.verify_module_integrity(strict=True, manifest_path=missing)


def test_skip_env_honored(integrity_env, monkeypatch):
    monkeypatch.setenv("MAOP_SKIP_INTEGRITY", "1")
    ok, reason = license_mod.verify_module_integrity()
    assert ok
    assert reason == "skipped"
