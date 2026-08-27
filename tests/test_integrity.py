"""Module integrity manifest tests (P0 #7): sign → verify → tamper detect.

Exercises the full integrity pipeline:
  - ``scripts/sign_enterprise_modules.py`` helpers (collect + sign)
  - ``maop.enterprise.license.verify_module_integrity`` (verify)

The manifest must live at the real ``maop/enterprise/`` location because
``verify_module_integrity`` resolves module files relative to the
manifest's parent directory. The fixture signs with an EPHEMERAL keypair
(patch ``_PUBLIC_KEY_PATH``) and restores any pre-existing manifest on
teardown, so the repo state is untouched.
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
MANIFEST_PATH = ENTERPRISE_DIR / "_integrity_manifest.json"
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
    """Ephemeral Ed25519 keypair + patched public key + real manifest path."""
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

    original = MANIFEST_PATH.read_bytes() if MANIFEST_PATH.exists() else None
    yield private_key, _load_sign_tool()
    # restore repo state
    if original is not None:
        MANIFEST_PATH.write_bytes(original)
    elif MANIFEST_PATH.exists():
        MANIFEST_PATH.unlink()


def _sign_and_write(private_key, tool) -> dict:
    files = tool.collect_module_hashes(ENTERPRISE_DIR)
    manifest = tool.build_and_sign(files, private_key, "2026-08-28T00:00:00Z")
    MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
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
    private_key, tool = integrity_env
    _sign_and_write(private_key, tool)
    ok, reason = license_mod.verify_module_integrity()
    assert ok, reason
    assert reason == "ok"


def test_tampered_module_detected(integrity_env):
    private_key, tool = integrity_env
    _sign_and_write(private_key, tool)
    target = ENTERPRISE_DIR / "ha.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# tampered\n")
        ok, reason = license_mod.verify_module_integrity()
        assert not ok
        assert "maop/enterprise/ha.py" in reason
    finally:
        target.write_bytes(original)
    # restored → verification passes again
    ok, reason = license_mod.verify_module_integrity()
    assert ok, reason


def test_forged_manifest_signature_rejected(integrity_env):
    private_key, tool = integrity_env
    manifest = _sign_and_write(private_key, tool)
    # corrupt the signature (attacker without the private key cannot re-sign)
    sig = str(manifest["signature"])
    manifest["signature"] = ("AAAA" if not sig.startswith("AAAA") else "BBBB") + sig[4:]
    MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
    ok, reason = license_mod.verify_module_integrity()
    assert not ok
    assert "signature" in reason


def test_missing_manifest_fails(integrity_env):
    private_key, tool = integrity_env
    _sign_and_write(private_key, tool)
    MANIFEST_PATH.unlink()
    ok, reason = license_mod.verify_module_integrity()
    assert not ok
    assert "manifest not found" in reason


def test_strict_mode_raises(integrity_env):
    private_key, tool = integrity_env
    _sign_and_write(private_key, tool)
    MANIFEST_PATH.unlink()
    with pytest.raises(license_mod.ModuleTamperError):
        license_mod.verify_module_integrity(strict=True)


def test_skip_env_honored(integrity_env, monkeypatch):
    monkeypatch.setenv("MAOP_SKIP_INTEGRITY", "1")
    ok, reason = license_mod.verify_module_integrity()
    assert ok
    assert reason == "skipped"
