#!/usr/bin/env python3
"""Sign MAOP Enterprise modules for tamper detection (P0 #7).

遍历 ``maop/enterprise/**/*.py`` 计算 SHA-256，用 Ed25519 私钥对
规范化 manifest 签名，输出 ``maop/enterprise/_integrity_manifest.json``。
运行时由 ``maop.enterprise.license.verify_module_integrity()`` 验证。

Manifest 格式（与 verify_module_integrity 的 canonical payload 严格一致）::

    {
      "version": 1,
      "signed_at": "<ISO-8601 UTC>",
      "tool": "sign_enterprise_modules.py",
      "files": {"maop/enterprise/xxx.py": "<sha256 hex>", ...},
      "signature": "<base64url(Ed25519(canonical_json))>"
    }

canonical_json = json.dumps({files, signed_at, tool, version},
                            sort_keys=True, separators=(",", ":"))

Usage:
    python scripts/sign_enterprise_modules.py --key scripts/test_signing_key.pem
    python scripts/sign_enterprise_modules.py --key /secure/prod_signing_key.pem

生产签名必须由持有生产私钥的发布流程执行；本仓库中的测试密钥
签出的 manifest 仅用于 CI/开发。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_TOOL_NAME = "sign_enterprise_modules.py"
_MANIFEST_VERSION = 1


def collect_module_hashes(enterprise_dir: Path) -> dict[str, str]:
    """计算 maop/enterprise 下所有 .py 文件的 SHA-256。

    返回 {"maop/enterprise/rel/path.py": "<hex>"}，键格式与
    verify_module_integrity 的路径还原逻辑匹配。
    """
    repo_root = enterprise_dir.parent.parent  # maop/enterprise → repo root
    files: dict[str, str] = {}
    for py in sorted(enterprise_dir.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        rel = py.relative_to(repo_root).as_posix()
        files[rel] = hashlib.sha256(py.read_bytes()).hexdigest()
    return files


def build_and_sign(
    files: dict[str, str], private_key: Ed25519PrivateKey, signed_at: str
) -> dict[str, object]:
    """构造 manifest 并签名（canonical payload 与验证端一致）。"""
    payload = json.dumps(
        {
            "files": files,
            "signed_at": signed_at,
            "tool": _TOOL_NAME,
            "version": _MANIFEST_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = private_key.sign(payload)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return {
        "version": _MANIFEST_VERSION,
        "signed_at": signed_at,
        "tool": _TOOL_NAME,
        "files": files,
        "signature": sig_b64,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign MAOP Enterprise modules (integrity manifest)"
    )
    parser.add_argument(
        "--key",
        default="scripts/test_signing_key.pem",
        help="Ed25519 private key path (relative to repo root)",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output manifest path (default: maop/enterprise/_integrity_manifest.json)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    key_path = repo_root / args.key
    if not key_path.exists():
        print(f"ERROR: private key not found at {key_path}", file=sys.stderr)
        sys.exit(1)

    key_data = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        print(
            f"ERROR: expected an Ed25519 private key, got {type(private_key).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)

    enterprise_dir = repo_root / "maop" / "enterprise"
    if not enterprise_dir.is_dir():
        print(f"ERROR: enterprise package not found at {enterprise_dir}", file=sys.stderr)
        sys.exit(1)

    files = collect_module_hashes(enterprise_dir)
    if not files:
        print("ERROR: no .py modules found under maop/enterprise", file=sys.stderr)
        sys.exit(1)

    signed_at = datetime.now(timezone.utc).isoformat()
    manifest = build_and_sign(files, private_key, signed_at)

    out_path = (
        Path(args.out) if args.out
        else enterprise_dir / "_integrity_manifest.json"
    )
    out_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(
        f"Signed {len(files)} modules → {out_path} "
        f"(key={key_path}, signed_at={signed_at})"
    )


if __name__ == "__main__":
    main()
